# 로컬 MongoDB Server에 연결
from pymongo import MongoClient
Connection = MongoClient("mongodb://localhost:27017/")
DB = Connection["TRANS_CS_DB"]
# print(dir(DB))
# print(DB)

from flask import Flask, render_template
from flask_socketio import SocketIO

# Python으로 csv파일 읽어와서 MongoDB에 저장
import pandas as pd


