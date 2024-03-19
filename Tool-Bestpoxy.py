import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import webbrowser
import requests
import concurrent.futures
import threading
import re
import winreg
import pycurl
from io import BytesIO
import json

# Khai báo biến toàn cục
total_proxies = 0
total_connectable = 0
total_non_connectable = 0

# Hàm để kiểm tra proxy
def check_proxy(proxy, connectable_text, non_connectable_text):
    global total_connectable
    global total_non_connectable
    global total_proxies
    try:
        proxies = {
            "http": f"http://{proxy['user']}:{proxy['password']}@{proxy['ip']}:{proxy['port']}",
            "https": f"http://{proxy['user']}:{proxy['password']}@{proxy['ip']}:{proxy['port']}"
        }
        response = requests.get("http://www.google.com", proxies=proxies, timeout=10)
        if response.status_code == 200:
            connectable_text.insert(tk.END, f"{proxy['ip']}:{proxy['port']}:{proxy['user']}:{proxy['password']}\n")
            total_connectable += 1
        else:
            non_connectable_text.insert(tk.END, f"{proxy['ip']}:{proxy['port']}:{proxy['user']}:{proxy['password']}\n")
            total_non_connectable += 1
    except:
        non_connectable_text.insert(tk.END, f"{proxy['ip']}:{proxy['port']}:{proxy['user']}:{proxy['password']}\n")
        total_non_connectable += 1
    finally:
        update_proxy_labels()

def update_proxy_labels():
    total_proxy_label.config(text=f"Tổng số proxy: {total_proxies}")
    connectable_label.config(text=f"Proxy có thể kết nối: {total_connectable}")
    non_connectable_label.config(text=f"Proxy không thể kết nối: {total_non_connectable}")

def check_proxies():
    global total_proxies
    total_proxies = 0
    global total_connectable
    total_connectable = 0
    global total_non_connectable
    total_non_connectable = 0
    
    proxies = text_area.get("1.0", "end-1c").split("\n")
    connectable_text.delete("1.0", tk.END)
    non_connectable_text.delete("1.0", tk.END)
    total_proxies = len(proxies)

    for proxy in proxies:
        if proxy:
            proxy_parts = proxy.split(":")
            if len(proxy_parts) == 4:
                ip, port, user, password = proxy_parts
                threading.Thread(target=check_proxy, args=({"ip": ip, "port": port, "user": user, "password": password}, connectable_text, non_connectable_text)).start()
            elif len(proxy_parts) == 2:
                ip, port = proxy_parts
                threading.Thread(target=check_proxy, args=({"ip": ip, "port": port, "user": "", "password": ""}, connectable_text, non_connectable_text)).start()


# Hàm để kiểm tra proxy và các hàm khác...

def extract_and_format_proxies(proxy_input):
    pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}:[^:\s]+:[^:\s]+\b")
    valid_proxies = pattern.findall(proxy_input.replace('\t', ' '))
    return '\n'.join(valid_proxies)

def format_and_display_proxies():
    proxy_input = proxy_text_box.get("1.0", tk.END)
    formatted_proxies = extract_and_format_proxies(proxy_input)
    output_text_box.delete('1.0', tk.END)
    output_text_box.insert(tk.END, formatted_proxies)


# Hàm cho Tab 3
def extract_and_format_proxies(proxy_input):
    pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}:[^:\s]+:[^:\s]+\b")
    valid_proxies = pattern.findall(proxy_input.replace('\t', ' '))
    return '\n'.join(valid_proxies)

def format_and_display_proxies_tab3():
    proxy_input = left_text_entry.get("1.0", tk.END)
    formatted_proxies = extract_and_format_proxies(proxy_input)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, formatted_proxies)

def check_duplicates():
    left_lines = left_text_entry.get("1.0", "end-1c").split('\n')
    right_lines = right_text_entry.get("1.0", "end-1c").split('\n')
    result_text.delete(1.0, tk.END)
    for left_line in left_lines:
        if not left_line:
            continue
        if left_line in right_lines:
            result_text.insert(tk.END, f"Dòng trùng: {left_line}\n")
        else:
            result_text.insert(tk.END, f"Dòng không trùng: {left_line}\n")

def check_duplicates():
    global left_text_entry, right_text_entry, result_text
    # Lấy dữ liệu và loại bỏ khoảng trắng
    left_lines_raw = left_text_entry.get("1.0", "end-1c").split('\n')
    right_lines_raw = right_text_entry.get("1.0", "end-1c").split('\n')

    left_lines = [line.replace(" ", "") for line in left_lines_raw]
    right_lines = [line.replace(" ", "") for line in right_lines_raw]

    result_text.delete(1.0, tk.END)
    left_text_entry.tag_remove("highlight", "1.0", "end")
    right_text_entry.tag_remove("highlight", "1.0", "end")
    
    for i, left_line in enumerate(left_lines):
        if not left_line:
            continue
        if left_line in right_lines:
            # Bôi đen dòng trùng lặp
            tag_occurrences(left_text_entry, left_lines_raw[i], "highlight", "yellow")
            tag_occurrences(right_text_entry, right_lines_raw[right_lines.index(left_line)], "highlight", "yellow")
            result_text.insert(tk.END, f"Dòng trùng: {left_lines_raw[i]}\n")
        else:
            result_text.insert(tk.END, f"Dòng không trùng: {left_lines_raw[i]}\n")


def tag_occurrences(text_widget, text_to_tag, tag_name, color):
    start_index = "1.0"
    while True:
        start_index = text_widget.search(text_to_tag, start_index, stopindex="end")
        if not start_index:
            break
        end_index = f"{start_index}+{len(text_to_tag)}c"
        text_widget.tag_add(tag_name, start_index, end_index)
        text_widget.tag_config(tag_name, background=color)
        start_index = end_index

def remove_duplicates():
    global left_text_entry, right_text_entry
    # Loại bỏ khoảng trắng trước khi so sánh
    left_lines = set(left_text_entry.get("1.0", "end-1c").split('\n'))
    right_lines = set(right_text_entry.get("1.0", "end-1c").split('\n'))

    # Loại bỏ dòng trùng lặp
    duplicates = set(line.replace(" ", "") for line in left_lines).intersection(set(line.replace(" ", "") for line in right_lines))
    
    # Xóa văn bản hiện tại và chỉ chèn lại những dòng không trùng
    right_text_entry.delete("1.0", tk.END)
    for line in right_lines:
        if line.replace(" ", "") not in duplicates:
            right_text_entry.insert(tk.END, line + "\n")




# Tạo giao diện chính
root = tk.Tk()
root.title("TOOL BESTPROXY.VN")
root.configure(bg="#f0f0f0")
root.geometry("1200x600")

# Cấu hình style cho Notebook và Tabs
style = ttk.Style()
style.configure("TNotebook",  borderwidth=1)
style.configure("TNotebook.Tab", background="#cccccc", foreground="#000000", padding=[20, 10], font=('Helvetica', 10, 'bold'))

# Tạo Notebook
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both")

# Tạo các tab
tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)
tab3 = ttk.Frame(notebook)
tab4 = ttk.Frame(notebook)
tab5 = ttk.Frame(notebook)

notebook.add(tab1, text="Check Live Proxy")
notebook.add(tab2, text="Lọc Proxy")
notebook.add(tab3, text="Kiểm Tra Trùng Lặp")
notebook.add(tab4, text="Mua Proxy và Liên Hệ")


# Tab 1: Kiểm tra Proxy - Đặt các widget cho tab này
label = tk.Label(tab1, text="Nhập danh sách proxy định dạng IP:PORT:USER:PASS (mỗi dòng một proxy, chú ý xóa dấu cách thừa):", bg="#f0f0f0", fg="blue", font=("Arial", 13, "bold"))
label.pack(padx=10, pady=10, anchor='w')

text_area = scrolledtext.ScrolledText(tab1, height=10, width=75, font=("Arial", 13))
text_area.pack(padx=10, pady=5)

button = tk.Button(tab1, text="Kiểm tra", command=check_proxies, bg="green", fg="white", font=("Arial", 13, "bold"))
button.pack(padx=10, pady=5)

result_frame = tk.Frame(tab1, bg="#f0f0f0")
result_frame.pack(padx=10, pady=5, fill='x', expand=True)

total_proxy_label = tk.Label(result_frame, text="Tổng số proxy: 0", bg="#f0f0f0", fg="black", font=("Arial", 13, "bold"))
total_proxy_label.pack(padx=10, pady=5, anchor='w')

connectable_label = tk.Label(result_frame, text="Proxy có thể kết nối: 0", bg="#f0f0f0", fg="green", font=("Arial", 13, "bold"))
connectable_label.pack(padx=10, pady=5, anchor='w')

non_connectable_label = tk.Label(result_frame, text="Proxy không thể kết nối: 0", bg="#f0f0f0", fg="red", font=("Arial", 13, "bold"))
non_connectable_label.pack(padx=10, pady=5, anchor='w')

connectable_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=45, height=10, bg="white", fg="black", font=("Arial", 13))
connectable_text.pack(side='left', padx=10, pady=5, fill='both', expand=True)

non_connectable_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, width=45, height=10, bg="white", fg="black", font=("Arial", 13))
non_connectable_text.pack(side='right', padx=10, pady=5, fill='both', expand=True)


# Tab 2: Extract & Format Proxies
proxy_label = tk.Label(tab2, text="Nhập proxy muốn lọc (cách nhau bằng dấu cách hoặc tab):", bg="#f0f0f0", fg="blue", font=("Arial", 12, "bold"))
proxy_label.pack(pady=10)
proxy_text_box = scrolledtext.ScrolledText(tab2, height=10, width=75, font=("Arial", 12))
proxy_text_box.pack(pady=10)
process_button = tk.Button(tab2, text="Lọc Proxy", command=format_and_display_proxies, bg="green", fg="white", font=("Arial", 12, "bold"))
process_button.pack(pady=10)
output_label = tk.Label(tab2, text="Kết quả sau khi kiểm tra và lọc:", bg="#f0f0f0", fg="blue", font=("Arial", 12))
output_label.pack(pady=10)
output_text_box = scrolledtext.ScrolledText(tab2, height=10, width=75, font=("Arial", 12))
output_text_box.pack(pady=10)



# Tạo Tab 3: Kiểm tra dòng trùng

# Các widget cho Tab 3
# Tạo khung chứa cho hai ô nhập văn bản và kết quả
input_frame = tk.Frame(tab3)
input_frame.pack(fill="x", padx=5, pady=5)

# Ô nhập văn bản bên trái
left_text_entry = scrolledtext.ScrolledText(input_frame, height=18, width=50, font=("Arial", 12))
left_text_entry.pack(side="left", padx=(0, 5), expand=True)

# Ô nhập văn bản bên phải
right_text_entry = scrolledtext.ScrolledText(input_frame, height=18, width=50, font=("Arial", 12))
right_text_entry.pack(side="right", padx=(5, 0), expand=True)

# Nút kiểm tra và xóa các dòng trùng
check_button = tk.Button(tab3, text="Kiểm tra Dòng Trùng",  command=check_duplicates, bg="green", fg="white", font=("Arial", 12, "bold"))
check_button.pack(pady=(5, 0))

remove_duplicates_button = tk.Button(tab3, text="Xóa Các Dòng Trùng", command=remove_duplicates, bg="red", fg="white", font=("Arial", 12, "bold"))
remove_duplicates_button.pack(pady=5)

# Hiển thị kết quả
result_text = scrolledtext.ScrolledText(tab3, height=11, width=80, font=("Arial", 12))
result_text.pack(padx=5, pady=(5, 0))


# Tạo tab 4
# Widget cho Tab 4
contact_label = tk.Label(tab4, text="Để mua proxy hoặc liên hệ, vui lòng truy cập các liên kết dưới đây:", bg="#f0f0f0", fg="blue", font=("Arial", 12, "bold"))
contact_label.pack(pady=10)

# Hàm mở liên kết trong trình duyệt mặc định
def open_link(link):
    webbrowser.open_new_tab(link)

# Nút để mở liên kết mua proxy
buy_proxy_button = tk.Button(tab4, text="Mua Proxy", command=lambda: open_link("https://bestproxy.vn/?a=login"), bg="blue", fg="white", font=("Arial", 12, "bold"))
buy_proxy_button.pack(pady=5)

# Nút để mở liên kết liên hệ
contact_button = tk.Button(tab4, text="Liên Hệ", command=lambda: open_link("https://t.me/bedaudone1"), bg="green", fg="white", font=("Arial", 12, "bold"))
contact_button.pack(pady=5)




# Tạo Tab 5: Kết Nối Proxy
tab5 = ttk.Frame(notebook)
notebook.add(tab5, text="Kết Nối Proxy")

def remove_spaces_tabs(event):
    # Xóa tất cả dấu tab và dấu cách từ chuỗi nhập vào
    entry_text = proxy_entry.get()
    entry_text = entry_text.replace('\t', '').replace(' ', '')
    proxy_entry.delete(0, tk.END)
    proxy_entry.insert(0, entry_text)

def parse_proxy(proxy_str):
    parts = proxy_str.split(':')
    if len(parts) == 3:  # Không cần nhập mật khẩu
        proxy_ip, proxy_port, proxy_user = parts
        return proxy_ip, proxy_port, proxy_user, None
    elif len(parts) == 4:  # Có nhập mật khẩu
        proxy_ip, proxy_port, proxy_user, proxy_pass = parts
        return proxy_ip, proxy_port, proxy_user, proxy_pass
    else:
        return None

def set_system_proxy(proxy_ip, proxy_port, proxy_user, proxy_pass):
    try:
        # Mở key đăng ký chứa cài đặt proxy trong Registry
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)

        # Thiết lập cấu hình proxy trong Registry
        winreg.SetValueEx(reg_key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(reg_key, "ProxyServer", 0, winreg.REG_SZ, f"{proxy_ip}:{proxy_port}")

        # Nếu cần xác thực proxy, cài đặt tên người dùng và mật khẩu
        if proxy_user and proxy_pass:
            winreg.SetValueEx(reg_key, "ProxyUser", 0, winreg.REG_SZ, proxy_user)
            winreg.SetValueEx(reg_key, "ProxyPass", 0, winreg.REG_SZ, proxy_pass)

        # Đóng key đăng ký
        winreg.CloseKey(reg_key)

        status_label.config(text="Connected", fg="green")
    except Exception as e:
        print(f"Lỗi khi cài đặt proxy: {str(e)}")

def get_ip_info(ip_address):
    try:
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, f'http://ip-api.com/json/{ip_address}')
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()

        # Phân tích cú pháp kết quả JSON
        ip_info = json.loads(buffer.getvalue().decode('utf-8'))
        if ip_info['status'] == 'success':
            return ip_info
        else:
            return None
    except pycurl.error as e:
        print(f"Error getting IP info: {e}")
        return None

def enable_proxy():
    proxy_str = proxy_entry.get()
    proxy_info = parse_proxy(proxy_str)
    if proxy_info:
        proxy_ip, proxy_port, proxy_user, proxy_pass = proxy_info
        set_system_proxy(proxy_ip, proxy_port, proxy_user, proxy_pass)
        try:
            # Sử dụng PyCURL để lấy địa chỉ IP công cộng
            buffer = BytesIO()
            c = pycurl.Curl()
            c.setopt(c.URL, 'https://api.ipify.org?format=json')
            c.setopt(c.PROXY, f'{proxy_ip}:{proxy_port}')
            if proxy_user and proxy_pass:
                c.setopt(c.PROXYUSERPWD, f'{proxy_user}:{proxy_pass}')
            c.setopt(c.WRITEDATA, buffer)
            c.setopt(c.SSL_VERIFYPEER, 0)  # Lưu ý vấn đề bảo mật khi sử dụng tùy chọn này
            c.setopt(c.SSL_VERIFYHOST, 0)
            c.perform()
            c.close()

            # Phân tích JSON để lấy ip_address
            ip_info_json = json.loads(buffer.getvalue().decode('utf-8'))
            ip_address = ip_info_json.get('ip', None)

            if ip_address:
                # Lấy thông tin chi tiết về địa chỉ IP
                ip_label.config(text=f"IP Address: {ip_address}",font=("Arial", 12, "bold"))
                detailed_ip_info = get_ip_info(ip_address)
                if detailed_ip_info:
                    country_label.config(text=f"Country: {detailed_ip_info['country']}",font=("Arial", 12, "bold"))
                    region_label.config(text=f"Region: {detailed_ip_info['regionName']}",font=("Arial", 12, "bold"))
                    city_label.config(text=f"City: {detailed_ip_info['city']}",font=("Arial", 12, "bold"))
                    status_label.config(text="Connected", fg="green",font=("Arial", 12, "bold"))
                else:
                    # Clear previous info if unable to get new info
                    country_label.config(text="Country: N/A",font=("Arial", 12, "bold"))
                    region_label.config(text="Region: N/A",font=("Arial", 12, "bold"))
                    city_label.config(text="City: N/A",font=("Arial", 12, "bold"))
                    status_label.config(text="Connected", fg="green",font=("Arial", 12, "bold"))
            else:
                status_label.config(text="Không thể lấy địa chỉ IP của proxy", fg="red",font=("Arial", 12, "bold"))
        except pycurl.error as e:
            status_label.config(text="Lỗi khi kết nối đến proxy", fg="red",font=("Arial", 12, "bold"))
    else:
        status_label.config(text="Thông tin proxy không hợp lệ", fg="red",font=("Arial", 12, "bold"))

def disable_proxy():
    try:
        # Mở key đăng ký chứa cài đặt proxy trong Registry
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)

        # Vô hiệu hóa proxy bằng cách thiết lập ProxyEnable thành 0
        winreg.SetValueEx(reg_key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

        # Đóng key đăng ký
        winreg.CloseKey(reg_key)

        status_label.config(text="Disconnected", fg="red",font=("Arial", 12, "bold"))
    except Exception as e:
        print(f"Lỗi khi tắt proxy: {str(e)}",font=("Arial", 12, "bold"))

# Thêm các widget vào Tab 5
tk.Label(tab5, text="Nhập thông tin proxy (ip:port:user:pass):",bg="#f0f0f0", fg="blue", font=("Arial", 12, "bold")).pack()
proxy_entry = tk.Entry(tab5, width=50,font=("Arial", 12, "bold"))
proxy_entry.pack(pady=1)

enable_button = tk.Button(tab5, text="Kết Nối", command=enable_proxy, bg="green", fg="white", font=("Arial", 12, "bold"))
enable_button.pack(pady=5)

disable_button = tk.Button(tab5, text="Ngắt Kết Nối", command=disable_proxy, bg="red", fg="white", font=("Arial",12, "bold"))
disable_button.pack()

status_label = tk.Label(tab5, text="Disconnected", fg="red",font=("Arial", 12, "bold"))
status_label.pack()

# Thêm Labels để hiển thị thông tin IP và quốc gia, tỉnh, thành phố
ip_label = tk.Label(tab5, text="IP Address: N/A",font=("Arial", 12, "bold"))
ip_label.pack()

country_label = tk.Label(tab5, text="Country: N/A",font=("Arial", 12, "bold"))
country_label.pack()

region_label = tk.Label(tab5, text="Region: N/A",font=("Arial", 12, "bold"))
region_label.pack()

city_label = tk.Label(tab5, text="City: N/A",font=("Arial", 12, "bold"))
city_label.pack()

# Liên kết sự kiện với Entry widget để loại bỏ dấu tab và dấu cách
proxy_entry.bind('<KeyRelease>', remove_spaces_tabs)



# Chạy giao diện chính
root.mainloop()
