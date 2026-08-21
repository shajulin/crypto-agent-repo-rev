package cryptoagents

import akka.actor.typed.{ActorRef, ActorSystem, Behavior}
import akka.actor.typed.scaladsl.Behaviors
import java.nio.file.{Files, Paths}
import scala.concurrent.Await
import scala.concurrent.duration._
import scala.jdk.CollectionConverters._

object Protocol {
  sealed trait Msg
  final case class Finding(device: String, agent: String, note: String) extends Msg
  case object AllStarted extends Msg
}

object Llm {
  val base: String  = sys.env.getOrElse("OLLAMA_BASE_URL", "http://ollama:11434")
  val model: String = sys.env.getOrElse("OLLAMA_MODEL", "llama3.2:3b")

  final case class Out(tier: Option[String], reasoning: String, latencyMs: Long)

  private val Levels = Set("critical", "high", "medium", "low")

  def explain(device: String, ev: ujson.Value, causes: List[String]): Out = {
    val cfg  = ev("config"); val meas = ev("measurements")
    val prompt =
      s"""You are an IIoT cryptographic-posture analyst. Assess ONE device from the
         |evidence and reply with ONLY a JSON object, nothing else:
         |{"risk_level":"critical|high|medium|low","reasoning":"<2 sentences naming the
         |concrete weaknesses: rng, cert, hash, curve, tls, secure boot, firmware>"}
         |Device $device evidence:
         |  aggregate_risk=${ev("aggregate_risk").num}
         |  rng_quality=${meas("rng_quality").str}, cert_status=${meas("cert_status").str}
         |  hash=${cfg("hash").str}, curve=${cfg("curve").str}, tls=${cfg("tls").str}
         |  secure_boot=${cfg("secure_boot").bool}, secure_element=${cfg("secure_element").bool}
         |  detected_issues=${causes.mkString(",")}""".stripMargin

    val body = ujson.Obj("model" -> model, "prompt" -> prompt, "stream" -> false,
                         "options" -> ujson.Obj("temperature" -> 0))
    val t0 = System.currentTimeMillis()
    try {
      val r = requests.post(s"$base/api/generate", data = ujson.write(body),
                            headers = Map("Content-Type" -> "application/json"),
                            readTimeout = 300000, connectTimeout = 15000, check = false)
      val latency = System.currentTimeMillis() - t0
      val text = ujson.read(r.text())("response").str
      val js   = text.indexOf('{'); val je = text.lastIndexOf('}')
      if (js >= 0 && je > js) {
        val parsed = ujson.read(text.substring(js, je + 1))
        val tier   = parsed.obj.get("risk_level").map(_.str.toLowerCase.trim)
        val reason = parsed.obj.get("reasoning").map(_.str).getOrElse(text.trim)
        Out(tier.filter(Levels.contains), reason.take(400), latency)
      } else Out(None, text.trim.take(400), latency)
    } catch {
      case e: Throwable =>
        System.err.println(s"[akka] LLM call FAILED: ${e.getClass.getName}: ${e.getMessage}")
        Out(None, s"LLM unreachable (${e.getClass.getSimpleName}); rule-based fallback",
            System.currentTimeMillis() - t0)
    }
  }
}

object ConfigActor {
  import Protocol._
  def apply(reply: ActorRef[Msg]): Behavior[(String, ujson.Value)] =
    Behaviors.receiveMessage { case (device, ev) =>
      val cfg = ev("config")
      val issues = scala.collection.mutable.ListBuffer[String]()
      if (!cfg("secure_boot").bool && !cfg("secure_element").bool) issues += "no_root_of_trust"
      if (!ev("config").obj.get("updatable").forall(_.bool)) issues += "not_updatable"
      reply ! Finding(device, "ConfigActor", issues.mkString(","))
      Behaviors.same
    }
}

object CryptoActor {
  import Protocol._
  def apply(reply: ActorRef[Msg]): Behavior[(String, ujson.Value)] =
    Behaviors.receiveMessage { case (device, ev) =>
      val cfg = ev("config"); val meas = ev("measurements")
      val issues = scala.collection.mutable.ListBuffer[String]()
      if (meas("rng_quality").str == "weak") issues += "weak_rng"
      if (meas("cert_status").str == "EXPIRED") issues += "expired_cert"
      if (cfg("hash").str == "SHA-1") issues += "deprecated_hash"
      if (cfg("curve").str == "P-224") issues += "below_par_curve"
      if (cfg("tls").str != "1.3") issues += "outdated_tls"
      reply ! Finding(device, "CryptoActor", issues.mkString(","))
      Behaviors.same
    }
}

object Supervisor {
  import Protocol._

  private var llmLatencyMs: Long = 0L
  private var llmValid: Int = 0
  private var llmTotal: Int = 0

  def apply(evidence: Map[String, ujson.Value], outPath: String): Behavior[Msg] =
    Behaviors.setup { ctx =>
      val pending = scala.collection.mutable.Map[String, scala.collection.mutable.Map[String, String]]()
      evidence.keys.foreach(d => pending(d) = scala.collection.mutable.Map())
      val reports = scala.collection.mutable.Map[String, ujson.Obj]()

      val cfgActor = ctx.spawn(ConfigActor(ctx.self), "config")
      val cryActor = ctx.spawn(CryptoActor(ctx.self), "crypto")
      evidence.foreach { case (d, ev) => cfgActor ! (d, ev); cryActor ! (d, ev) }

      Behaviors.receiveMessage {
        case Finding(device, agent, note) =>
          pending(device)(agent) = note
          if (pending(device).size == 2) {
            reports(device) = riskLead(device, evidence(device), pending(device).toMap, ctx)
            if (reports.size == evidence.size) {
              writeOut(outPath, reports.toMap)
              ctx.log.info(s"[akka] wrote $outPath (${reports.size} devices, " +
                           s"llm_valid=$llmValid/$llmTotal, llm_ms=$llmLatencyMs)")
              Behaviors.stopped
            } else Behaviors.same
          } else Behaviors.same
        case AllStarted => Behaviors.same
      }
    }

  def riskLead(device: String, ev: ujson.Value, findings: Map[String, String],
               ctx: akka.actor.typed.scaladsl.ActorContext[Protocol.Msg]): ujson.Obj = {
    val risk = ev("aggregate_risk").num
    val level = if (risk >= 0.6) "critical" else if (risk >= 0.35) "high"
                else if (risk >= 0.2) "medium" else "low"
    val causes = findings.values.flatMap(_.split(",")).filter(_.nonEmpty).toList
    val root = causes.headOption.getOrElse("none")
    val recs = scala.collection.mutable.ListBuffer[String]()
    if (causes.contains("weak_rng")) recs += "Replace PRNG with a hardware TRNG"
    if (causes.contains("expired_cert")) recs += "Renew the X.509 certificate"
    if (causes.contains("deprecated_hash")) recs += "Migrate off SHA-1"
    if (recs.isEmpty) recs += "Maintain posture; monitor cert lifetime"

    val out = Llm.explain(device, ev, causes)
    llmLatencyMs += out.latencyMs; llmTotal += 1
    out.tier.foreach(_ => llmValid += 1)
    ctx.log.info(s"[akka] $device LLM tier=${out.tier.getOrElse("n/a")} (${out.latencyMs} ms)")

    val obj = ujson.Obj(
      "device" -> device,
      "risk_level" -> level,
      "root_cause" -> root,
      "recommendations" -> ujson.Arr.from(recs.map(s => ujson.Str(s))),
      "compliance" -> (if (causes.nonEmpty) "NON-COMPLIANT" else "COMPLIANT"),
      "reasoning" -> out.reasoning
    )
    out.tier.foreach(t => obj("raw_risk_level") = t)
    obj
  }

  def writeOut(path: String, reports: Map[String, ujson.Obj]): Unit = {
    val rawValid = if (llmTotal > 0) llmValid.toDouble / llmTotal else 0.0
    val obj = ujson.Obj(
      "reports" -> ujson.Obj.from(reports.map { case (k, v) => k -> v }),
      "meta" -> ujson.Obj(
        "framework" -> "akka", "mode" -> "akka-typed-actors+ollama",
        "total_tool_calls" -> 0,
        "raw_valid_rate" -> math.round(rawValid * 1000) / 1000.0,
        "total_latency_ms" -> llmLatencyMs.toDouble,
        "features" -> ujson.Obj(
          "llm" -> (llmValid > 0), "tools" -> false, "autonomy" -> false,
          "memory" -> true, "multi_agent" -> true, "jvm_free" -> false))
    )
    Files.write(Paths.get(path), ujson.write(obj, indent = 2).getBytes("UTF-8"))
  }
}

object Main {
  def main(args: Array[String]): Unit = {
    val base = if (args.nonEmpty) args(0) else "."
    val inPath = s"$base/evidence_input.json"
    val outPath = s"$base/akka_result.json"
    val raw = new String(Files.readAllBytes(Paths.get(inPath)), "UTF-8")
    val parsed = ujson.read(raw)
    val evidence = parsed("evidence").obj.toMap
    val system = ActorSystem(Supervisor(evidence, outPath), "crypto-akka")
    Await.result(system.whenTerminated, 60.minutes)
  }
}
