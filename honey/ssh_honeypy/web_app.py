# Import library dependencies.
from dash import Dash, html, dash_table, dcc, Input, Output
import dash_bootstrap_components as dbc
import plotly.express as px
from dash_bootstrap_templates import load_figure_template
from pathlib import Path
from dotenv import load_dotenv
import os
import sys

# Import project python file dependencies.
from dashboard_data_parser import *
from honeypy import *

# Import ML components
try:
    from ml.integration import HoneypotMLAnalyzer
    from ml.dashboard import get_ml_dashboard_components
    ML_ENABLED = True
except ImportError:
    ML_ENABLED = False
    print("[!] ML components not available. ML features will be disabled.")

# Constants.
# Get base directory of where user is running honeypy from.
base_dir = base_dir = Path(__file__).parent.parent
# Source creds_audits.log & cmd_audits.log file path.
creds_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'creds_audits.log'
cmd_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'cmd_audits.log'
# Load dotenv() to capture environment variable.
dotenv_path = Path('public.env')
load_dotenv(dotenv_path=dotenv_path)

# Pass log files to dataframe conversion.
creds_audits_log_df = parse_creds_audits_log(creds_audits_log_local_file_path)
cmd_audits_log_df = parse_cmd_audits_log(cmd_audits_log_local_file_path)

# Pass dataframes to top_10 calculator to get the top 10 values in the dataframe.
top_ip_address = top_10_calculator(creds_audits_log_df, "ip_address")
top_usernames = top_10_calculator(creds_audits_log_df, "username")
top_passwords = top_10_calculator(creds_audits_log_df, "password")
top_cmds = top_10_calculator(cmd_audits_log_df, "Command")

# Pass IP address to calculate country code, then to the top_10 calculator.
# get_ip_to_country = ip_to_country_code(creds_audits_log_df)
# top_country = top_10_calculator(get_ip_to_country, "Country_Code")

# Python Dash (& Dash Bootstrap) Constants.
# Load the Cyborg theme from Python Dash Bootstrap.
load_figure_template(["cyborg"])
dbc_css = ("https://cdn.jsdelivr.net/gh/AnnMarieW/dash-bootstrap-templates@V1.0.4/dbc.min.css")

# Source the HONEYPY logo for dashboard.
image = 'assets/images/honeypy-logo-white.png'

# Declare Dash App, apply CYBORG theme.
app = Dash(__name__, external_stylesheets=[dbc.themes.CYBORG, dbc_css])
# Provide web page title and Favicon.
app.title = "HONEYPY"
app._favicon = "../assets/images/honeypy-favicon.ico"

# Set the value to True in (public.env) if you want country code lookup as default. This does have impact on performance by default.
# If the script is erroring out with a Rate Limiting Error (HTTP CODE 429), set country to False in (public.env), this will not look up country codes and will not show dashboard.
country = os.getenv('COUNTRY')
# Fucntion to get country code lookup if country = True. This does have impact on performance. Default is set to False.
def country_lookup(country):
    if country == 'True':
        get_ip_to_country = ip_to_country_code(creds_audits_log_df)
        top_country = top_10_calculator(get_ip_to_country, "Country_Code")
        message = dbc.Col(dcc.Graph(figure=px.bar(top_country, x="Country_Code", y='count')), style={'width': '33%', 'display': 'inline-block'})
    else:
        message = "No Country Panel Defined"
    return message

# Generate tables using DBC (Dash Bootstrap Component) library.
tables = html.Div([
        dbc.Row([
            dbc.Col(
                dash_table.DataTable(
                    data=creds_audits_log_df.to_dict('records'),
                    columns=[{"name": "IP Address", 'id': 'ip_address'}],
                    style_table={'width': '100%', 'color': 'black'},
                    style_cell={'textAlign': 'left', 'color': '#2a9fd6'},
                    style_header={'fontWeight': 'bold'},
                    page_size=10
                ),
            ),
            dbc.Col(
                dash_table.DataTable(
                    data=creds_audits_log_df.to_dict('records'),
                    columns=[{"name": "Usernames", 'id': 'username'}],
                    style_table={'width': '100%'},
                    style_cell={'textAlign': 'left', 'color': '#2a9fd6'},
                    style_header={'fontWeight': 'bold'},
                    page_size=10
                ),
            ),
        
            dbc.Col(
                dash_table.DataTable(
                    data=creds_audits_log_df.to_dict('records'),
                    columns=[{"name": "Passwords", 'id': 'password'}],
                    style_table={'width': '100%','justifyContent': 'center'},
                    style_cell={'textAlign': 'left', 'color': '#2a9fd6'},
                    style_header={'fontWeight': 'bold'},
                    page_size=10
                ),
            ),       
        ])
])

# Apply dark theme to the tables. Had to cast this to an HTML.Div with className to get the dark theme.
apply_table_theme = html.Div(
    [tables],
    className="dbc"
)

# Create navbar with image and text.
navbar = dbc.Navbar(
    dbc.Container(
        [
            html.A(
                # Use row and col to control vertical alignment of logo / brand
                dbc.Row(
                    [
                        dbc.Col(html.Img(src=image, height="80px")),
                        dbc.Col(dbc.NavbarBrand("HONEYPY Dashboard", className="ml-2")),
                    ],
                    align="center",
                ),
                href="https://github.com/collinsmc23/ssh_honeypot",
            ),
        ]
    ),
    color="dark",
    dark=True,
)

# Initialize ML analyzer if available
ml_analyzer = None
if ML_ENABLED:
    try:
        ml_analyzer = HoneypotMLAnalyzer(cmd_audits_log_local_file_path)
        # Get ML dashboard components
        ml_card, ml_insights_callback = get_ml_dashboard_components(ml_analyzer)
        # Start background analysis
        ml_analyzer.start_background_analysis()
    except Exception as e:
        print(f"[!] Error initializing ML components: {e}")
        ML_ENABLED = False

# App layout set by Dash library. Provide children layout here for the html.Div of dash.
app.layout = html.Div([
    navbar,
    # Add refresh interval for dashboard updates
    dcc.Interval(
        id='interval-component',
        interval=30*1000,  # in milliseconds (30 seconds)
        n_intervals=0
    ),
    dbc.Container([
        dbc.Row([
            dbc.Col(html.H1("HONEYPY Dashboard", className="text-center"))
        ]),
        dbc.Row([
            dbc.Col(html.H6("Collected IP Addresses, Username, Passwords, and Command Attempts.", className="text-center"))
        ]),
        # Section 1: Graphs
        html.Div([
            dbc.Row([
                dbc.Col(dcc.Graph(figure=px.bar(top_ip_address, x='ip_address', y='count')), style={'width': '33%', 'display': 'inline-block'}),
                dbc.Col(dcc.Graph(figure=px.bar(top_usernames, x='username', y='count')), style={'width': '33%', 'display': 'inline-block'}),
                dbc.Col(dcc.Graph(figure=px.bar(top_passwords, x='password', y='count')), style={'width': '33%', 'display': 'inline-block'}),
            ])
        ]),
        # If country = True, display the country lookup graph.
        html.Div([
            dbc.Row([
                country_lookup(country),
                dbc.Col(dcc.Graph(figure=px.bar(top_cmds, x='Command', y='count')), style={'width': '33%', 'display': 'inline-block'}),
            ])
        ]),
        # Section 2: Tables for IP address, username, and password.
        apply_table_theme,
        # Section 3: ML Insights (if enabled)
        dbc.Row([
            dbc.Col(ml_card if ML_ENABLED else html.Div(), width=12)
        ]) if ML_ENABLED else html.Div(),
    ])
])

# Add refresh interval for dashboard updates (defined inline in layout)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")

