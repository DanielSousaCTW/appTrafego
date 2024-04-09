import customtkinter as ctk
from CTkTable.ctktable import CTkTable
import tkinter.messagebox
import tkinter
import subprocess
import json
from api_security import SecurityAnalysisToolkit

class Functions:
    def __init__(self):
        self.value = 0
    # Função para mudar a aparancia (Light, Dark, System)
    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    # Função para mudar a escala do UI
    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        ctk.set_widget_scaling(new_scaling_float)

    # Função para criar o pdf report (Incomplete)
    def sidebar_button_event(self):
        print("Generate PDF Report")

    # Abrir nova tab para inserir
    def open_input_dialog_event(self):
        dialog = ctk.CTkInputDialog(text = "Insert an IP:", title = "IP Input")
        print("CTkInputDialog:", dialog.get_input())

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.functions = Functions()    # Dar import à class com as funções  
        self.toolkit = SecurityAnalysisToolkit()
        values = [
            [" IP "],
            []
        ]                  

        # Set the title of the window
        self.title("Interface")

        # Set the appearance mode and default color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        # Configure window size
        self.geometry(f"{1100}x{580}")

        # Configure grid layout (3x3)
        self.grid_columnconfigure(1, weight = 1)        # Make column 1 expandable
        self.grid_columnconfigure((2, 3), weight = 0)   # Keep columns 2 and 3 at their minimum size
        self.grid_rowconfigure((0, 1), weight = 1)      # Make rows 0 and 1 expandable

        # Get screen width and height
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        # Calculate position
        x = (screen_width / 2) - (1100 / 2)
        y = (screen_height / 2) - (580 / 2)

        # Set the position of the window to the center of the screen
        self.geometry(f"{1100}x{580}+{int(x)}+{int(y)}")

        # Create sidebar frame with widgets
        self.sidebar_frame = ctk.CTkFrame(self, width = 140, corner_radius = 0)
        self.sidebar_frame.grid(row = 0, column = 0, rowspan = 4, sticky = "nsew")                                              # Position the sidebar frame in the grid layout
        self.sidebar_frame.grid_rowconfigure(4, weight = 1)                                                                     # Configure the row in the grid layout of the sidebar frame
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text = "Tools")                                                      # Create a label for the logo and position it in the grid layout of the sidebar frame
        self.logo_label.grid(row = 0, column = 0, padx = 20, pady = (20, 10))
        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, text = "Appearance Mode:", anchor = "w")                  # Create a label for the appearance mode option and position it in the grid layout of the sidebar frame
        self.appearance_mode_label.grid(row = 5, column = 0, padx = 20, pady = (10, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values = ["Light", "Dark", "System"],          # Create an option menu for the appearance mode and position it in the grid layout of the sidebar frame
                                                            command = self.functions.change_appearance_mode_event)              
        self.appearance_mode_optionemenu.grid(row = 6, column = 0, padx = 20, pady = (10, 10))
        self.scaling_label = ctk.CTkLabel(self.sidebar_frame, text = "UI Scaling:", anchor = "w")                               # Create a label for the UI scaling option and position it in the grid layout of the sidebar frame
        self.scaling_label.grid(row = 7, column = 0, padx = 20, pady = (10, 0))
        self.scaling_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame, values = ["80%", "90%", "100%", "110%", "120%"],       # Create an option menu for the UI scaling and position it in the grid layout of the sidebar frame
                                                    command = self.functions.change_scaling_event)
        self.scaling_optionemenu.grid(row = 8, column = 0, padx = 20, pady = (10, 20))

        # Create table
        self.table = CTkTable(master = self, values = values, command = True, hover = True)

        # Pack the table and start the Tkinter event loop
        self.table.grid(row = 0, column = 1, padx = 20, pady = 20, sticky = "n")

        # Create tabview
        self.tabview = ctk.CTkTabview(self, width = 250)                                            # Adjust width
        self.tabview.grid(row = 0, column = 2, padx = (10, 10), pady = (10, 10), sticky = "nsew")   # Adjust padding
        self.tabview.add("Scan Hosts")                                                              # Adjust tab name
        self.tabview.tab("Scan Hosts").grid_columnconfigure((0, 1, 2), weight = 1)                  # Configure grid of individual tabs

        # Tab: New Hosts
        self.entry = ctk.CTkEntry(self.tabview.tab("Scan Hosts"), placeholder_text = "Insert subnet here")
        self.entry.grid(row = 2, column = 0, padx = 20, pady = (20, 20), sticky = "nsew")
        self.string_input_button = ctk.CTkButton(self.tabview.tab("Scan Hosts"), text = "Scan subnet",
                                                command = lambda: self.scan_and_save(self.entry.get(), self.table)) 
        self.string_input_button.grid(row = 2, column = 1, padx = 20, pady = (10, 10))
    
    def scan_and_save(self, subnet, table):
        self.toolkit.scan_network(subnet)
        print(self.toolkit.live_hosts)
        # Add the header 'IP' to the list of scanned IPs
        values = [["IP"]] + [[ip] for ip in self.toolkit.live_hosts]

        # Update table
        table.update_values(values = values)

def main():
    # Create an instance of MyApp
    app = App()

    # Start the main loop
    app.mainloop()

if __name__ == "__main__":
    main()