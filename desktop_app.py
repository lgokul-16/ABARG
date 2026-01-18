import os
import threading
import webview
import sys
from app import app, socketio

# Hide console for GUI app
if getattr(sys, 'frozen', False):
    import pyi_splash

def start_server():
    # Run Flask-SocketIO server
    # We set allow_unsafe_werkzeug=True because pywebview is a controlled environment
    socketio.run(app, port=5000, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    # Start server in a separate thread
    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()

    # Close splash screen if it exists
    if getattr(sys, 'frozen', False) and 'pyi_splash' in sys.modules:
        pyi_splash.close()

    # Create window
    webview.create_window('ABARG Chat', 'http://127.0.0.1:5000', width=1200, height=800, resizable=True)
    
    # Start webview
    webview.start()
