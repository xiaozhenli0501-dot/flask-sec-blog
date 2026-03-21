import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, Post

def init_database():
    with app.app_context():
        print("正在初始化数据库...")
        
        # 创建所有表
        db.create_all()
        
        # 检查是否已有用户
        if User.query.count() == 0:
            print("创建默认用户...")
            
            # 创建admin用户
            admin = User(username='admin')
            admin.set_password('admin123')
            
            # 创建test用户
            test_user = User(username='test')
            test_user.set_password('test123')
            
            db.session.add(admin)
            db.session.add(test_user)
            db.session.commit()
            
            print("创建示例文章...")
            # 创建文章
            posts = [
                Post(
                    title='欢迎使用Flask博客系统',
                    content='这是系统的第一篇示例文章。这是一个基于Flask开发的个人博客系统，支持用户登录、文章发布和管理等功能。',
                    author_id=admin.id
                ),
                Post(
                    title='Flask入门教程',
                    content='Flask是一个轻量级的Python Web框架，简单易用但功能强大。本教程将介绍Flask的基本使用方法。',
                    author_id=admin.id
                ),
                Post(
                    title='Python Web开发心得',
                    content='分享一些我在Python Web开发过程中的经验和技巧，希望能对大家有所帮助。',
                    author_id=test_user.id
                ),
                Post(
                    title='如何写好技术博客',
                    content='技术博客写作的技巧：1.明确主题 2.结构清晰 3.代码示例 4.图文并茂 5.总结经验教训。',
                    author_id=admin.id
                )
            ]
            
            for post in posts:
                db.session.add(post)
            
            db.session.commit()
            
            print(f"✓ 已创建 {User.query.count()} 个用户")
            print(f"✓ 已创建 {Post.query.count()} 篇文章")
            print("\n默认登录账户：")
            print("用户1: admin / admin123")
            print("用户2: test / test123")
        else:
            print("数据库已有数据，跳过初始化。")

if __name__ == '__main__':
    init_database()
