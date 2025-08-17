
#!/usr/bin/env python3

# Import the configured app with routes already registered
from app import app

# Verify routes are registered
print("=== Routes Registered ===")
for rule in app.url_map.iter_rules():
    print(f"{rule.rule} -> {rule.endpoint}")
print(f"Total routes: {len(list(app.url_map.iter_rules()))}")
print("=========================")

if __name__ == '__main__':
    # Run without reloader to avoid route registration issues
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
