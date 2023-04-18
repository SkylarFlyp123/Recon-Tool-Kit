from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import logging
from flask_sqlalchemy import SQLAlchemy
# from flask_wkhtmltopdf import Wkhtmltopdf

app = Flask(__name__)
app.static_folder = 'static'
# Configure MySQL connection details
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/rtk' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# wkhtmltopdf = Wkhtmltopdf(app)

# Create an instance of SQLAlchemy
db = SQLAlchemy(app)

from recon_tool_kit import routes
from recon_tool_kit import models



