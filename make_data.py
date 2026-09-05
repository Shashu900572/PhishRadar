import random

brands = ['sbi', 'hdfc', 'icici', 'paypal', 'google', 'amazon', 'netflix', 'microsoft', 'apple', 'zerodha']
tlds = ['.com', '.in', '.net', '.org', '.tk', '.xyz', '.info', '.co']
paths = ['/login', '/verify', '/account-update', '/security-alert', '/auth', '/webscr', '/portal']

rows = ['url,label,shannon_entropy,url_length,has_ip,target_brand']

# 550 Phishing URLs
for i in range(550):
    b = random.choice(brands)
    t = random.choice(tlds)
    p = random.choice(paths)
    if random.random() > 0.5:
        ip = f"{random.randint(11,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        url = f"http://{ip}/{b}{p}"
        has_ip = 1
    else:
        url = f"http://{b}-verify-login{i}{t}{p}"
        has_ip = 0
    entropy = round(random.uniform(3.8, 4.9), 2)
    rows.append(f"{url},phishing,{entropy},{len(url)},{has_ip},{b}")

# 550 Legitimate URLs
for i in range(550):
    b = random.choice(brands)
    url = f"https://www.{b}.com/dashboard/portal/{i}"
    entropy = round(random.uniform(2.1, 3.2), 2)
    rows.append(f"{url},legitimate,{entropy},{len(url)},0,{b}")

with open('dataset.csv', 'w') as f:
    f.write('\n'.join(rows))

print(f"Expanded dataset generated with {len(rows)-1} rows!")