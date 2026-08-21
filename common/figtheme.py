import matplotlib.pyplot as plt

BG = "#171821"                         
PANEL = "#20222e"                    
FG = "#e6e6ec"                    
GRID = "#343747"                       

                                                                
PALETTE = {
    "problem": "#ff6b6b",                                    
    "ok": "#51cf66",                                     
    "accent": "#4dabf7",                             
    "llm": "#20c997",                             
    "warn": "#ffa94d",              
    "purple": "#b197fc",
    "muted": "#868e96",
}
                                               
SERIES = ["#4dabf7", "#51cf66", "#ffa94d", "#b197fc", "#20c997", "#ff6b6b"]


def apply():
    plt.rcParams.update({
        "figure.facecolor": BG, "savefig.facecolor": BG, "axes.facecolor": PANEL,
        "text.color": FG, "axes.labelcolor": FG, "axes.titlecolor": FG,
        "axes.edgecolor": GRID, "xtick.color": FG, "ytick.color": FG,
        "grid.color": GRID, "grid.alpha": 0.35, "axes.grid": True,
        "axes.grid.axis": "y", "font.size": 10, "figure.titlesize": 13,
        "axes.titlesize": 11, "legend.framealpha": 0.2,
    })
