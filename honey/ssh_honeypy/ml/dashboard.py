"""
Dashboard integration for ML insights.
Provides components to add ML visualizations to the honeypot dashboard.
"""
import plotly.express as px
import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output
import json
from pathlib import Path
from .config import ANALYTICS_DIR


def get_ml_insights(ml_analyzer=None):
    """
    Get the latest ML insights or generate new ones if none exist.
    
    Args:
        ml_analyzer: Optional analyzer instance to generate insights
        
    Returns:
        dict: ML insights or empty dict if none available
    """
    if ml_analyzer:
        # Try to get insights from analyzer
        return ml_analyzer.get_latest_insights()
    
    # Try to load from file
    latest_path = Path(ANALYTICS_DIR) / 'latest_insights.json'
    if latest_path.exists():
        try:
            with open(latest_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading insights from file: {e}")
    
    return {}


def create_ml_figures(insights):
    """
    Create ML visualization figures for the dashboard.
    
    Args:
        insights: Dictionary of ML insights
        
    Returns:
        list: Plotly figures for visualization
    """
    figures = []
    
    # Skip if no insights or missing key data
    if not insights or 'category_percentages' not in insights:
        return figures
    
    # Create category distribution pie chart
    if insights['category_percentages']:
        category_fig = px.pie(
            names=list(insights['category_percentages'].keys()),
            values=list(insights['category_percentages'].values()),
            title="Command Categories",
            template="cyborg"  # Match the existing dashboard theme
        )
        figures.append(category_fig)
    
    # Create top commands bar chart
    if 'top_commands_by_category' in insights:
        # Extract top commands across categories
        all_top_commands = []
        for category, cmds in insights['top_commands_by_category'].items():
            for cmd, count in cmds.items():
                all_top_commands.append({
                    'command': cmd,
                    'count': count,
                    'category': category
                })
        
        # Sort and take top 10
        if all_top_commands:
            all_top_commands = sorted(all_top_commands, key=lambda x: x['count'], reverse=True)[:10]
            
            top_commands_fig = px.bar(
                all_top_commands,
                x='command',
                y='count',
                color='category',
                title="Top Commands by Frequency",
                template="cyborg"
            )
            figures.append(top_commands_fig)
    
    return figures


def get_ml_dashboard_components(ml_analyzer=None):
    """
    Get the dashboard components for ML insights.
    
    Args:
        ml_analyzer: Optional analyzer instance
        
    Returns:
        tuple: (layout, callback_function)
    """
    # Get insights
    insights = get_ml_insights(ml_analyzer)
    
    # Create ML card for dashboard
    ml_card = dbc.Card(
        dbc.CardBody([
            html.H4("Machine Learning Insights", className="card-title"),
            html.Div(id="ml-insights-container")
        ]),
        className="mt-3"
    )
    
    # Define the callback function for updating ML insights
    def ml_insights_callback(n_intervals):
        # Get fresh insights on each update
        current_insights = get_ml_insights(ml_analyzer)
        figures = create_ml_figures(current_insights)
        
        if not figures:
            return html.P("No ML insights available yet. Run the honeypot to collect more data.")
            
        # Build attack focus insight text
        attack_focus = current_insights.get('attack_focus', 'Unknown')
        
        # Return the complete layout
        return [
            html.Div([
                # Attack focus insight
                html.Div([
                    html.H5("Attack Focus Analysis"),
                    html.P(f"This attacker appears to be focused on: {attack_focus}", className="lead")
                ], className="mb-4"),
                
                # Charts in a responsive grid
                dbc.Row([
                    dbc.Col(dcc.Graph(figure=figures[0]), md=6) if len(figures) > 0 else None,
                    dbc.Col(dcc.Graph(figure=figures[1]), md=6) if len(figures) > 1 else None,
                ])
            ])
        ]
    
    return ml_card, ml_insights_callback
