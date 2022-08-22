import os
import glob


from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from .modelCreation import PreProcessing
from .modelCreation import PreProcessingAccess
from .models import Note
from . import db
import json

from pathlib import Path
views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash('Votre note est courte!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note ajoutée!', category='success')

    return render_template("home.html", user=current_user)


@views.route('/delete-note', methods=['POST'])
def delete_note():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})

@views.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@views.route('/errorlogdash')
@login_required
def errordashboard():
    return render_template("Error log.html", user=current_user)

@views.route('/modelCreation', methods=['POST'])
def predictAttack():
    from main import app

    pathFile = os.path.abspath(app.config['UPLOAD_FOLDER']) + "\*"
    pathj = glob.glob(pathFile)
    for file in pathj:
        os.remove(file)
    pathOutput = os.path.abspath(app.config['OutputError']) + "\*"
    pathOutput = glob.glob(pathOutput)
    for file in pathOutput:
        os.remove(file)

    filesLog = request.files.getlist("errorLogFilename[]")
    pathFile =os.path.abspath(app.config['UPLOAD_FOLDER'])
    pathOutput = os.path.abspath(app.config['OutputError'])
    for fileLog in filesLog:
        fileLog.save(os.path.join(app.config['UPLOAD_FOLDER'], fileLog.filename))
    PreProcessing(pathFile, pathOutput)
    return render_template("home.html", user=current_user)



@views.route('/modelCreationAccess', methods=['POST'])
def accessGenerate():
    from main import app

    pathFile = os.path.abspath(app.config['ACCESS_UPLOAD_FOLDER']) + "\*"
    pathj = glob.glob(pathFile)
    for file in pathj:
        os.remove(file)
    pathOutput = os.path.abspath(app.config['OutputAccess']) + "\*"
    pathOutput = glob.glob(pathOutput)
    for file in pathOutput:
        os.remove(file)

    filesLog = request.files.getlist("accessLogFilename[]")
    pathFile =os.path.abspath(app.config['ACCESS_UPLOAD_FOLDER'])
    pathOutput = os.path.abspath(app.config['OutputAccess'])
    for fileLog in filesLog:
        fileLog.save(os.path.join(app.config['ACCESS_UPLOAD_FOLDER'], fileLog.filename))
    PreProcessingAccess(pathFile, pathOutput)
    return render_template("home.html", user=current_user)