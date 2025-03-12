from flask import Flask, request, jsonify, abort, render_template, make_response, redirect, url_for
from openai import OpenAI
import base64
import uuid

import configparser

# 初始化 ConfigParser 对象
config = configparser.ConfigParser()

# 读取配置文件
config.read('config.ini')

app = Flask(__name__)

# 初始化 OpenAI 客户端
client = OpenAI(
    api_key=config.get('openai', 'api_key'),
    base_url=config.get('openai', 'base_url')
)

# 存储历史对话的列表
conversation_history = []
# 存储令牌和用户信息的映射关系
user_token_mapping = {}

def generate_and_set_token(username, password, resp):
    """
    生成令牌并设置到响应的 Cookie 中
    :param username: 用户名
    :param password: 密码
    :param resp: 响应对象
    :return: 生成的令牌
    """
    token = str(uuid.uuid4())
    user_token_mapping[token] = (username, password)
    resp.set_cookie('token', token)
    return token

def authenticate():
    """
    验证请求的认证信息，先尝试从 cookie 中获取，若失败则使用 HTTP 基本认证
    """
    print("尝试从 cookie 中获取令牌")
    token = request.cookies.get('token')
    print(f"从 Cookie 中获取的令牌: {token}")
    if token and token in user_token_mapping:
        print("找到有效的令牌，认证成功")
        return  # 认证成功
    print("认证失败，尝试基本认证")
    auth = request.headers.get('Authorization')
    print(f"请求头部的 Authorization 信息: {auth}")
    if not auth or not auth.startswith('Basic '):
        print("缺少基本认证信息")
        abort(401)
    encoded_credentials = auth.split(' ')[1]
    decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
    input_username, input_password = decoded_credentials.split(':')
    valid_username = config.get('auth', 'username')
    valid_password = config.get('auth', 'password')
    if input_username == valid_username and input_password == valid_password:
        print("基本认证成功，生成令牌")
        token = str(uuid.uuid4())
        user_token_mapping[token] = (valid_username, valid_password)
        resp = make_response()
        resp.set_cookie('token', token)
        return
    print("基本认证失败")
    abort(401)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        # 调用认证函数进行验证
        authenticate()
        valid_username = config.get('auth', 'username')
        valid_password = config.get('auth', 'password')
        # 创建响应对象，并重定向到聊天页面
        resp = make_response(redirect(url_for('chat_page')))
        # 生成令牌并设置到 Cookie 中
        print("生成令牌")
        generate_and_set_token(valid_username, valid_password, resp)
        print("设置令牌")
        print(f"登录成功，设置令牌: {resp.headers.get('Set-Cookie')}")
        return resp
    except Exception as e:
        # 若认证失败，返回错误信息和 401 状态码
        return jsonify({"error": str(e)}), 401

@app.route('/chat_page')
def chat_page():
    authenticate()
    return render_template('chat_page.html')

@app.route('/chat_page', methods=['POST'])
@app.route('/chat', methods=['POST'])
def chat():
    authenticate()
    try:
        data = request.get_json()
        user_message = data.get('message')
        if not user_message:
            return jsonify({"error": "Missing 'message' in request body"}), 400

        conversation_history.append({"role": "user", "content": user_message})

        response = client.chat.completions.create(
            model="*****YOUR OWN MODEL API*****",
            messages=conversation_history,
            stream=False,
            max_tokens=4096,
            temperature=1.03,
            presence_penalty=-0.3,
            frequency_penalty=0.3,
            top_p=0.9,
        )

        answer = response.choices[0].message.content
        conversation_history.append({"role": "assistant", "content": answer})
        return jsonify({"answer": answer})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/new_conversation', methods=['POST'])
def new_conversation():
    # 验证认证信息
    authenticate()
    global conversation_history
    # 清空历史对话列表
    conversation_history = []
    return jsonify({"status": "New conversation started"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)