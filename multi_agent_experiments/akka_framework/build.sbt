ThisBuild / scalaVersion := "2.13.14"

lazy val akkaVersion = "2.8.5"

lazy val root = (project in file("."))
  .settings(
    name := "crypto-akka-agents",
    libraryDependencies ++= Seq(
      "com.typesafe.akka" %% "akka-actor-typed" % akkaVersion,
      "com.typesafe.akka" %% "akka-stream"      % akkaVersion,
      "com.lihaoyi"       %% "upickle"          % "3.3.1",
      "com.lihaoyi"       %% "requests"         % "0.9.0"
    ),
    Compile / mainClass := Some("cryptoagents.Main")
  )
