from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/sort', methods=['POST'])
def sort():
    data = request.json
    items = data.get("items")

    if not isinstance(items, list):
        return jsonify({"error": "Please provide a list under 'items'"}), 400

    try:
        sorted_items = sorted(items)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"sorted": sorted_items})

if __name__ == '__main__':
    app.run(port=5000)