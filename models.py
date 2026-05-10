#数据库设计，定义数据模型,定义用户和文章的数据库模型;
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash,check_password_hash
import time

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(50),unique=True,nullable=False)
    password_hash = db.Column(db.String(128),nullable=False)
    #created_at = db.Column(db.DateTime,default=datetime.utcnow)
    
    # 漏洞点 2：取消哈希加密，使用明文存储密码以配合靶场比较逻辑
    def set_password(self, password):
        self.password_hash = password # 直接存明文

    # 漏洞点 3：不安全的字符串逐位比对，导致时间侧信道攻击
    def check_password(self, password):
        # 长度不同时的耗时差异
        if len(self.password_hash) != len(password):
            time.sleep(0.5)
            return False

        # 长度相同时，逐字节比对
        for i in range(len(self.password_hash)):
            if self.password_hash[i] != password[i]:
                return False
            time.sleep(0.2)
        return True 

    #关联文章（一个用户可写多篇文章）
    posts = db.relationship('Post',backref='author',lazy=True)
    
    @property
    def is_active(self):
        return True #默认所有用户都是活跃的
    @property
    def is_authenticated(self):
        return True  # 对于已登录用户返回True   
    @property
    def is_anonymous(self):
        return False  # 对于真实用户返回False
    
    def get_id(self):
        return str(self.id)  # 返回用户的ID作为标识

    def __repr__(self):
        return f'<User {self.username}>'

    def delete_post(self,post_id):
        post = Post.query.get(post_id)
        if post and post.author_id == self.id:
            db.session.delete(post)
            db.session.commit()
            return True
        return False 

class Post(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    title = db.Column(db.String(200),nullable=False)
    content = db.Column(db.Text,nullable=False)
    timestamp = db.Column(db.DateTime,default=datetime.utcnow)
    #外键关联用户
    author_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)

    def can_delete(self, user):
        """检查用户是否有权限删除此文章"""
        return user and (user.id == self.author_id)
    @property
    def comment_count(self):
        return len(self.comments) if self.comments else 0

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=True)  # 是否审核通过
    is_anonymous = db.Column(db.Boolean, default=False)  # 是否匿名
    
    # 外键：评论属于哪篇文章
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    
    # 外键：评论的作者（可以为空，允许匿名评论）
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # 关系定义
    author = db.relationship('User', backref='comments')
    post = db.relationship('Post', backref=db.backref('comments', lazy=True, cascade='all, delete-orphan'))
    
    # 父评论ID（用于回复功能）
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)
    
    def __repr__(self):
        return f'<Comment {self.id} - {self.content[:50]}>'

# 评论点赞功能
class CommentLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# 评论通知功能
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
