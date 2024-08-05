from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from db import query_db, insert_db
import init_db
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Flask 애플리케이션의 시크릿 키 설정

# 로그 설정
logging.basicConfig(level=logging.DEBUG)

# 애플리케이션 시작 시 데이터베이스 초기화
init_db.init_db()

# 회원가입 폼 정의
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    # 사용자 이름 중복 검사
    def validate_username(self, username):
        user = query_db('SELECT * FROM users WHERE username = %s', (username.data,))
        if user:
            raise ValidationError('Username is already taken.')

# 로그인 폼 정의
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# 비밀번호 변경 폼 정의
class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

    def validate_current_password(self, current_password):
        user = query_db('SELECT * FROM users WHERE id = %s', (session['user_id'],), one=True)
        logging.debug(f'User for password validation: {user}')
        if not user or not check_password_hash(user[2], current_password.data):
            logging.debug('Current password validation failed')
            raise ValidationError('Current password is incorrect.')

# 메인 페이지 라우트
@app.route('/')
def index():
    return render_template('index.html')

# 회원가입 페이지 라우트
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        logging.debug(f'Original password: {form.password.data}, Hashed password: {hashed_password}')
        insert_db('INSERT INTO users (username, password) VALUES (%s, %s)', (form.username.data, hashed_password))
        flash('You have successfully registered!', 'success')
        user = query_db('SELECT * FROM users WHERE username = %s', (form.username.data,), one=True)
        logging.debug(f'Retrieved user after registration: {user}')
        insert_db('INSERT INTO activity_log (user_id, activity) VALUES (%s, %s)', (user[0], '회원가입'))
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# 로그인 페이지 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        logging.debug(f'Attempting login for user: {form.username.data}')
        user = query_db('SELECT * FROM users WHERE username = %s', (form.username.data,), one=True)
        if user:
            # 삭제된 사용자 확인
            deleted_user = query_db('SELECT * FROM deleted_users WHERE id = %s', (user[0],), one=True)
            if deleted_user:
                logging.debug(f'User {form.username.data} is in the deleted_users table')
                flash('귀하의 계정이 삭제되었습니다. 이 문제가 실수라고 생각되시면 지원팀에 문의해 주세요..', 'danger')
            else:
                # 비밀번호 확인
                if check_password_hash(user[2], form.password.data):
                    logging.debug(f'Password match for user: {form.username.data}')
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    flash('Login successful!', 'success')
                    try:
                        insert_db('INSERT INTO activity_log (user_id, activity) VALUES (%s, %s)', (user[0], '로그인'))
                        logging.debug('로그인 활동이 데이터베이스에 성공적으로 삽입되었습니다.')
                    except Exception as e:
                        logging.error(f"Failed to insert login activity: {e}")
                    return redirect(url_for('index'))
                else:
                    logging.debug('Password does not match')
                    flash('로그인 실패. 사용자 이름과 비밀번호를 확인해 주세요', 'danger')
        else:
            logging.debug('User not found')
            flash('로그인 실패. 사용자 이름과 비밀번호를 확인해 주세요.', 'danger')
    return render_template('login.html', form=form)

# 로그아웃 라우트
@app.route('/logout')
def logout():
    if 'user_id' in session:
        logging.debug(f'Logging out user: {session["user_id"]}')
        insert_db('INSERT INTO activity_log (user_id, activity) VALUES (%s, %s)', (session['user_id'], '로그아웃'))
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out!', 'success')
    return redirect(url_for('index'))

# 계정 삭제 라우트
@app.route('/delete_account')
def delete_account():
    if 'user_id' in session:
        user_id = session['user_id']
        try:
            logging.debug(f'Deleting account for user: {user_id}')
            
            # 활동 로그에 '회원탈퇴' 기록
            insert_db('INSERT INTO activity_log (user_id, activity) VALUES (%s, %s)', (user_id, '회원탈퇴'))
            logging.debug('Activity log for account deletion inserted successfully')

            # 삭제된 사용자 정보를 deleted_users 테이블에 저장
            user = query_db('SELECT * FROM users WHERE id = %s', (user_id,), one=True)
            if user:
                insert_db('INSERT INTO deleted_users (id, username) VALUES (%s, %s)', (user_id, user[1]))
                logging.debug(f'User {user_id} saved to deleted_users table')

            # # 사용자 계정 삭제 /관리자만 삭제 가능하게
            # insert_db('DELETE FROM users WHERE id = %s', (user_id,))
            # session.pop('user_id', None)
            # session.pop('username', None)
            # flash('탈퇴하셨습니다. 홈페이지로 돌아갑니다.', 'success')

        except Exception as e:
            logging.error(f"Failed to delete account: {e}")
            flash('계정 삭제 중 오류가 발생했습니다. 나중에 다시 시도해 주세요.', 'danger')
    else:
        logging.debug('No user is currently logged in.')
        flash('로그인 세션이 유효하지 않습니다.', 'warning')

    return redirect(url_for('index'))

# 비밀번호 변경 라우트
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = PasswordChangeForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.new_password.data)
        logging.debug(f'Changing password for user: {session["user_id"]}')
        try:
            insert_db('UPDATE users SET password = %s WHERE id = %s', (hashed_password, session['user_id']))
            insert_db('INSERT INTO activity_log (user_id, activity) VALUES (%s, %s)', (session['user_id'], '비밀번호 변경'))
            flash('Your password has been changed!', 'success')
        except Exception as e:
            logging.error(f"Failed to change password: {e}")
            flash('비밀번호 변경에 실패했습니다. 다시 시도해 주세요.', 'danger')
        return redirect(url_for('index'))
    else:
        logging.debug('Form validation failed')
    return render_template('change_password.html', form=form)

# 사이드바 메뉴 관련 페이지 라우트
@app.route('/manage_system')
def manage_system():
    return render_template('manage_system.html')

@app.route('/manage_movies')
def manage_movies():
    return render_template('manage_movies.html')

@app.route('/manage_people')
def manage_people():
    return render_template('manage_people.html')

@app.route('/manage_events')
def manage_events():
    return render_template('manage_events.html')

@app.route('/manage_influencers')
def manage_influencers():
    return render_template('manage_influencers.html')

@app.route('/manage_notifications')
def manage_notifications():
    return render_template('manage_notifications.html')

@app.route('/my_page')
def my_page():
    return render_template('my_page.html')

@app.route('/main_screen')
def main_screen():
    return render_template('main_screen.html')

if __name__ == '__main__':
    app.run(debug=True)
