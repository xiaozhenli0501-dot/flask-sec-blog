# -*- coding: utf-8 -*-
from sqlalchemy import text
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField,TextAreaField,SubmitField,PasswordField,HiddenField  
from wtforms.validators import DataRequired,Length,EqualTo 
from models import db, User, Post,Comment
from flask_bootstrap import Bootstrap
from datetime import datetime, date, time, timedelta
from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import generate_latest, REGISTRY, Counter, Histogram
import time
import logging
import re
import subprocess

# initial Flask
app = Flask(__name__)
metrics = PrometheusMetrics(app)
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency', ['method', 'endpoint'])

# --- ：自定义带 client_ip 标签的指标 (核心) ---
HTTP_REQUESTS_BY_CLIENT_IP = Counter(
    'http_requests_by_client_ip_total',
    'Request count by client IP',
    ['method', 'endpoint', 'status', 'client_ip']
)

AUTH_LOGIN_SUCCESSES = Counter(
    'auth_login_successes_total',
    'Number of successful logins',
    ['username', 'client_ip']
)

AUTH_LOGIN_FAILURES = Counter(
    'auth_login_failures_total',
    'Number of failed login attempts',
    ['username', 'client_ip']
)

app.config['SECRET_KEY'] = '6cb2a12c98893154bae50849801e13c4aba72864b8f26f7f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化扩展
db.init_app(app)

# 启用Bootstrap美化
Bootstrap(app)  

# 初始化登录管理
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # 未登录时跳转的页面
login_manager.login_message = '请先登录以访问此页面。'
login_manager.login_message_category = 'warning'

# 用户加载回调（Flask-Login必填）
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 创建数据库表（首次运行时执行）
with app.app_context():
    db.create_all()

# 定义注册表单
class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('密码', validators=[
        DataRequired(),
        Length(min=6, message='密码长度至少为6位')
    ])
    confirm_password = PasswordField('确认密码', validators=[
        DataRequired(),
        EqualTo('password', message='两次输入的密码不一致')
    ])
    submit = SubmitField('注册')

# 定义登录表单
class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired()])
    password = PasswordField('密码', validators=[DataRequired()])  # 改为 PasswordField
    submit = SubmitField('登录')

# 定义文章发表表单
class PostForm(FlaskForm):
    title = StringField('标题', validators=[DataRequired()])
    content = TextAreaField('内容', validators=[DataRequired()])
    submit = SubmitField('发布')

#定义评论发表表单
class CommentForm(FlaskForm):
    content = TextAreaField('评论内容', validators=[
        DataRequired(message='评论内容不能为空'),
        Length(min=1, max=1000, message='评论内容应在1-1000字之间')
    ])
    submit = SubmitField('发表评论')
    parent_id = HiddenField('父评论ID')

# 请求钩子
@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    if hasattr(request, 'start_time'):
        latency = time.time() - request.start_time
        REQUEST_LATENCY.labels(request.method, request.path).observe(latency)
    REQUEST_COUNT.labels(request.method, request.path).inc()

    # ---记录带 client_ip 的指标 ---
    HTTP_REQUESTS_BY_CLIENT_IP.labels(
        method=request.method,
        endpoint=request.path,
        status=response.status_code,
        client_ip=get_real_ip() # 使用下面定义的函数
    ).inc()

    return response

def get_real_ip():
    """获取真实客户端 IP"""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.remote_addr
    else:
        forwarded_for = request.environ['HTTP_X_FORWARDED_FOR']
        real_ip = forwarded_for.split(',')[0].strip()
        return real_ip

# 添加首页路由
@app.route('/')
def index():
    # 查询所有文章，按时间倒序排列
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=posts)

# 用户注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:  # 若已登录，直接跳转首页
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # 检查用户名是否已存在
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('用户名已存在，请选择其他用户名', 'danger')
            return render_template('register.html', form=form)
        
        # 创建新用户
        new_user = User(username=form.username.data)
        new_user.set_password(form.password.data)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('注册成功！请登录。', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'注册失败: {str(e)}', 'danger')
    
    return render_template('register.html', form=form)

# 用户登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        # 漏洞点 1：用户枚举漏洞，明确区分“用户名不存在”和“密码错误”
        if not user:
            logger.warning(
                f"USER_ENUMERATION username={form.username.data} ip={get_real_ip()}"
            )
            flash('用户名不存在', 'danger')  # 明确暴露用户名是否存在
            return render_template('login.html', form=form)
            
        if user.check_password(form.password.data):
            logger.info(
                f"LOGIN_SUCCESS username={user.username} ip={get_real_ip()}"
            )
            login_user(user)  
            AUTH_LOGIN_SUCCESSES.labels(username=user.username, client_ip=get_real_ip()).inc()
            flash(f'欢迎回来，{user.username}！', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            logger.warning(
                f"LOGIN_FAILED username={form.username.data} ip={get_real_ip()}"
            )

            AUTH_LOGIN_FAILURES.labels(username=form.username.data, client_ip=get_real_ip()).inc()
            flash('密码错误', 'danger')  # 明确暴露密码错误
            
    return render_template('login.html', form=form)

# 添加文章详情页路由
# 漏洞点 4： <post_id> 以允许传入非数字的 SQL Payload
@app.route('/post/<post_id>')
def post_detail(post_id):
    if any(char in post_id for char in ["'", '"', ";", "--", "union", "select"]):

        logger.error(
            f"SQLI_ATTEMPT ip={get_real_ip()} payload={post_id}"
        )
    try:
        # 故意使用字符串拼接，构造 SQL 注入点
        #query = text(f"id = {post_id}") 
        #post = Post.query.filter(query).first()
        post = Post.query.filter_by(id=post_id).first()  # 正常查询
    except Exception as e:
        # 靶场特性：暴露出数据库错误信息，便于实现报错注入
        return f"Database Error: {str(e)}", 500 

    if not post:
        return "404 Not Found", 404
        
    form = CommentForm() 
    return render_template('post_detail.html', post=post, form=form)

# 漏洞点 5：搜索功能中构造 LIKE 拼接注入点
@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    sqli_patterns = [
        'union',
        'select',
        'or 1=1',
        'sleep(',
        'benchmark(',
        '--'
    ]

    if any(pattern.lower() in keyword.lower() for pattern in sqli_patterns):

        logger.error(
            f"SQLI_ATTEMPT ip={get_real_ip()} payload={keyword}"
        )
    sqli_patterns = [
        'union',
        'select',
        'or 1=1',
        'sleep(',
        'benchmark(',
        '--'
    ]

    if any(pattern.lower() in keyword.lower() for pattern in sqli_patterns):

        logger.error(
            f"SQLI_ATTEMPT ip={get_real_ip()} payload={keyword}"
        )
    try:
        # 搜索关键词拼接产生 SQL 注入
        #query = text(f"title LIKE '%{keyword}%' OR content LIKE '%{keyword}%'")
        #posts = Post.query.filter(query).all()
        posts = Post.query.filter(
            (Post.title.contains(keyword)) | (Post.content.contains(keyword))
        ).all()  # 正常查询
    except Exception as e:
        return f"Database Error: {str(e)}", 500
        
    return render_template('index.html', posts=posts)

# 添加文章创建路由
@app.route('/create', methods=['GET', 'POST'])
@login_required  # 仅登录用户可访问
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        # 创建新文章并关联当前用户
        post = Post(
            title=form.title.data,
            content=form.content.data,
            author_id=current_user.id  # 作者为当前登录用户
        )
        db.session.add(post)
        db.session.commit()
        flash('文章发布成功！', 'success')
        return redirect(url_for('index'))  # 发布后跳转首页
    return render_template('create_post.html', form=form)

# 添加编辑功能和定义编辑页面路由
@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # 检查权限
    if post.author_id != current_user.id:
        flash('您没有权限编辑此文章', 'danger')
        return redirect(url_for('index'))
    
    form = PostForm()
    
    if request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('文章更新成功！', 'success')
        return redirect(url_for('post_detail', post_id=post.id))
    
    return render_template('create_post.html', form=form, post=post, editing=True)

# 添加文章删除功能以及路由信息
@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # 检查权限
    if not post.can_delete(current_user):
        flash('您没有权限删除此文章', 'danger')
        return redirect(url_for('index'))
    
    try:
        db.session.delete(post)
        db.session.commit()
        flash('文章已成功删除', 'success')
    except:
        db.session.rollback()
        flash('删除失败，请重试', 'danger')
    
    return redirect(url_for('index'))

# 发表评论
@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    
    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            post_id=post.id,
            author_id=current_user.id,
            parent_id=form.parent_id.data if form.parent_id.data else None
        )
        
        db.session.add(comment)
        db.session.commit()
        flash('评论发表成功！', 'success')
    else:
        flash('评论发表失败，请检查内容', 'danger')
    
    return redirect(url_for('post_detail', post_id=post.id))

# 编辑评论
@app.route('/comment/<int:comment_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # 权限检查：只能编辑自己的评论
    if comment.author_id != current_user.id:
        flash('您没有权限编辑此评论', 'danger')
        return redirect(url_for('post_detail', post_id=comment.post_id))
    
    form = CommentForm()
    
    if request.method == 'GET':
        form.content.data = comment.content
    
    if form.validate_on_submit():
        comment.content = form.content.data
        comment.timestamp = datetime.utcnow()  # 更新编辑时间
        db.session.commit()
        flash('评论更新成功！', 'success')
        return redirect(url_for('post_detail', post_id=comment.post_id))
    
    return render_template('edit_comment.html', form=form, comment=comment)

# 删除评论
@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id
    
    # 权限检查：评论作者或文章作者可以删除
    can_delete = (comment.author_id == current_user.id or 
                  comment.post.author_id == current_user.id)
    
    if not can_delete:
        flash('您没有权限删除此评论', 'danger')
        return redirect(url_for('post_detail', post_id=post_id))
    
    try:
        db.session.delete(comment)
        db.session.commit()
        flash('评论已删除', 'success')
    except:
        db.session.rollback()
        flash('删除失败，请重试', 'danger')
    
    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()  # 登出用户
    flash('已成功登出', 'info')
    return redirect(url_for('index'))

# metrics路由
@app.route('/metrics')
def metrics():
    from prometheus_client import generate_latest
    return generate_latest(REGISTRY)

# IP 封禁 Webhook 路由
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

def is_valid_ip(ip):
    """验证 IP 地址格式"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = [int(part) for part in ip.split('.')]
    return all(0 <= part <= 255 for part in parts)

def is_whitelisted_ip(ip):
    """检查 IP 是否在白名单中"""
    WHITELISTED_IPS = {'127.0.0.1', '192.168.1.1'}
    return ip in WHITELISTED_IPS

def execute_block_command(ip_addr):
    """执行封禁命令"""
    try:
        script_path = "/blog_project_test/block_ip.sh" 
        result = subprocess.run(["sudo",script_path,ip_addr],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
        logger.info(f"封禁脚本执行输出: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"执行封禁命令失败: {e.stderr}")
        return False
    except FileNotFoundError:
        logger.error(f"找不到封禁脚本，请检查路径: {script_path}")
        return False

@app.route('/webhook/block_ip', methods=['POST'])
def block_ip_webhook():
    """
    接收来自 Alertmanager 的 webhook，
    并根据 payload 中的 IP 信息执行封禁。
    """
    try:
        data = request.get_json()
        if not data:
            logger.error("Webhook 接收到无效的 JSON 数据。")
            return {"error": "Invalid JSON payload"}, 400

        alerts = data.get('alerts', [])
        if not alerts:
            logger.warning("Webhook 接收到了数据，但没有找到 'alerts' 数组。")
            return {"message": "No alerts found in payload"}, 200

        blocked_count = 0
        for alert in alerts:
            status = alert.get('status', '')
            ip_to_block = alert.get('labels', {}).get('source_ip') or alert.get('labels', {}).get('client_ip')

            if not ip_to_block:
                logger.warning(f"告警中未找到 IP 标签 (source_ip 或 client_ip): {alert.get('labels', {})}")
                continue

            if not is_valid_ip(ip_to_block):
                logger.error(f"无效的 IP 地址，拒绝封禁: {ip_to_block}")
                continue

            if is_whitelisted_ip(ip_to_block):
                logger.info(f"IP {ip_to_block} 在白名单中，跳过封禁。")
                continue

            if status == 'firing':
                success = execute_block_command(ip_to_block)
                if success:
                    logger.warning(
                        f"WEBHOOK_BLOCK ip={ip_to_block}"
                    )
                    blocked_count += 1
                else:
                    logger.error(f"封禁 IP {ip_to_block} 失败。")
            elif status == 'resolved':
                # 如果需要解封，在这里添加解封逻辑
                # execute_unblock_command(ip_to_block)
                pass

        return {"message": f"处理完毕，共封禁 {blocked_count} 个 IP"}, 200

    except Exception as e:
        logger.error(f"处理 Webhook 时发生错误: {e}")
        return {"error": "Internal Server Error"}, 500


if __name__ == '__main__':
    print("=" * 50)
    print("Flask 博客系统启动中...")
    print("访问地址: http://127.0.0.1:5000")
    print("外部访问: http://192.168.112.5:5000")
    print("按 Ctrl+C 停止服务")
    print("="*50)
    app.run(host='0.0.0.0', port=5000, debug=True)