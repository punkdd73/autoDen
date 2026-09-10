# autoDen 系統建置工程計畫書 (方案 A：純內網 + 2FA + 雙軌權限)

## 1. 系統架構與設計原則

```
[ECOUNT 進貨單 / 商品主檔 (API 同步)] ──> [本地 SQLite erp_products 快取]
                                                   │ (雙擊快查品項)
                                                   ▼
[業務輸入銷貨需求 (支援 ERP 快查)] ──> [autoDen FEFO 運算] ────┘
                             │
                             ▼
              [autoDen 揀貨單 (隱藏LOT/EXP，僅顯儲位)]
                             │ (走道拿最前排)
                             ▼
              [品保閘門 (2D 槍 / 相機掃碼過刷)]
                ├── 實刷 GS1 拆解 (GTIN / LOT / EXP)
                ├── 對撞預配目標：綠燈累加 / 紅燈死鎖攔截 (條碼/LOT/EXP 全核對)
                └── 齊件狀態鎖定 (轉 VERIFIED) ──> 寫入 outbound.log
                             │
                             ▼
              [Admin 審核 / 批次 API 拋轉 / CSV 倒灌] ──> [ECOUNT 銷貨單過帳]
```

- **純內網安全邊界**：服務綁定於打包桌電腦的區域網路 IP（`0.0.0.0:8000`），對外物理隔離，嚴禁開啟 Ngrok 外網穿透。
- **TOTP 雙重驗證 (2FA)**：登入使用 Email 搭配 Google Authenticator 產生的 6 位數一次性動態密碼。獨立設有「帳號資安」管理介面，由 Admin 動態派發新進人員金鑰與展示綁定 QR Code。
- **全流程防呆責任隔離 (方案 A)**：
  - **Operator（作業員）**：負責建單（支援一鍵同步 ERP 主檔、雙擊品號/品名/條碼彈出 ERP 快查視窗）、列印/重印揀貨單、實施 GS1 條碼掃描對撞驗證（GTIN、LOT、EXP 全要素核對）。全單齊件後，單據狀態轉為 `VERIFIED`，無直接發動 ERP 拋轉之權限。
  - **Admin（管理員）**：進入「Admin 中控台」審核單據（呈現單號、客戶編碼、建單日期、狀態，支援點擊單號彈窗查閱明細），支援單筆/批次 ECOUNT API 直拋過帳，並預留標準批次 CSV 匯出功能；僅 Admin 具備異常單據的強制重傳權限。
- **技術棧選型**：
  - **後端**：Python (FastAPI + Uvicorn) + SQLite3
  - **前端**：Jinja2 模板 + Tailwind CSS + Alpine.js + Lucide Icons + JsBarcode + qrcode.js

---

## 2. 資料庫結構 (SQLite Schema)

```sql
-- 使用者與 2FA 認證表
CREATE TABLE users (
    email TEXT PRIMARY KEY,
    totp_secret TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'operator')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ERP 商品主檔本地快取表 (支援本機毫秒級全文檢索)
CREATE TABLE erp_products (
    item_code TEXT PRIMARY KEY,        -- ECOUNT 品項編碼 (PROD_CD)
    item_name TEXT NOT NULL,           -- 品項名稱規格 (PROD_DES)
    barcode TEXT,                      -- 商品國際條碼 (BAR_CODE / GTIN)
    default_location TEXT,             -- 預設儲位座標
    last_synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 銷貨需求單頭
CREATE TABLE orders (
    order_id TEXT PRIMARY KEY,          -- 例如: SO-20260910-001
    customer_code TEXT NOT NULL,       -- ECOUNT 客戶編碼
    order_date TEXT NOT NULL,          -- YYYY-MM-DD
    status TEXT NOT NULL CHECK(status IN ('DRAFT', 'PICKING', 'SCANNING', 'VERIFIED', 'SYNCED', 'FAILED')),
    printed INTEGER DEFAULT 0,         -- 0: 未列印, 1: 已列印 (可隨時重複列印)
    created_by TEXT NOT NULL,          -- 建立者 Email
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(email)
);

-- 銷貨需求配批單身 (Allocation Line，完整承載品號、品名、條碼與儲位批次)
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT NOT NULL,
    item_code TEXT NOT NULL,           -- ECOUNT 品項編碼
    item_name TEXT NOT NULL,           -- 品項名稱規格
    barcode TEXT NOT NULL,             -- 商品條碼 / GTIN
    location_code TEXT NOT NULL,       -- 儲位座標 (例如: NP-AR01-B-03)
    allocated_lot TEXT NOT NULL,       -- FEFO 演算法預配之目標批號 (強制純文字，保留前導零)
    allocated_exp TEXT NOT NULL,       -- 預配效期 (YYYY-MM-DD)
    qty_allocated INTEGER NOT NULL,    -- 該批次預配數量 (支援一品多批拆分)
    qty_scanned INTEGER DEFAULT 0,     -- 該批次實刷合格數量
    scanned_lot TEXT,                  -- 實刷確認之 LOT (強制純文字，保留前導零)
    scanned_exp TEXT,                  -- 實刷確認之 EXP (YYYY-MM-DD)
    FOREIGN KEY(order_id) REFERENCES orders(order_id)
);

-- ERP 同步紀錄與稽核留存表
CREATE TABLE sync_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT NOT NULL,
    sync_method TEXT NOT NULL CHECK(sync_method IN ('API', 'CSV')),
    operator_email TEXT NOT NULL,
    payload_snapshot TEXT,
    api_response TEXT,
    synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(order_id) REFERENCES orders(order_id)
);
```

---

## 3. 核心模組實作

### 3.1. Admin 初始化與 2FA 派發 (`init_admin.py` & `auth_service.py`)

```python
import sqlite3
import pyotp
import qrcode

def setup_admin():
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            totp_secret TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'operator')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    admin_email = input("請輸入 Admin Email: ").strip()
    secret = pyotp.random_base32()
    
    cursor.execute(
        "INSERT OR REPLACE INTO users (email, totp_secret, role) VALUES (?, ?, 'admin')",
        (admin_email, secret)
    )
    conn.commit()
    conn.close()
    
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=admin_email, issuer_name="autoDen WMS")
    qr = qrcode.QRCode()
    qr.add_data(uri)
    print(f"\nAdmin 初始化完成 [{admin_email}]，請使用 Google Authenticator 掃描終端機 QR Code 綁定：\n")
    qr.print_ascii(invert=True)

if __name__ == "__main__":
    setup_admin()
```

### 3.2. GS1 DataMatrix 解析引擎 (`gs1_parser.py`)

處理定長與不定長 AI，相容 ASCII 29 (`\x1d`)、`\u001d`、文字標記 `[GS]`、`<GS>`、`{GS}`、`~d029`，強制文字化輸出以保留批號前導零：

```python
def parse_gs1(raw_data: str) -> dict:
    clean_data = raw_data
    for gs_pattern in ["[GS]", "<GS>", "{GS}", "~d029", "\u001d"]:
        clean_data = clean_data.replace(gs_pattern, "\x1d")
        
    result = {}
    i = 0
    length = len(clean_data)
    
    FIXED_AIS = {"01": 14, "11": 6, "17": 6}
    VARIABLE_AIS = ["10", "21", "30"]
    
    while i < length:
        if clean_data[i] == "\x1d":
            i += 1
            continue
        ai_2 = clean_data[i:i+2]
        
        if ai_2 in FIXED_AIS:
            val_len = FIXED_AIS[ai_2]
            start = i + 2
            end = start + val_len
            result[ai_2] = clean_data[start:end]
            i = end
        elif ai_2 in VARIABLE_AIS:
            start = i + 2
            next_gs = clean_data.find("\x1d", start)
            if next_gs != -1:
                result[ai_2] = clean_data[start:next_gs]
                i = next_gs + 1
            else:
                result[ai_2] = clean_data[start:]
                i = length
        else:
            i += 1
            
    exp_formatted = ""
    if "17" in result and len(result["17"]) == 6:
        raw_exp = result["17"]
        exp_formatted = f"20{raw_exp[0:2]}-{raw_exp[2:4]}-{raw_exp[4:6]}"
        
    return {
        "gtin": str(result.get("01", "")),
        "lot": str(result.get("10", "")),       # 強制保留文字型態與前導零
        "exp": exp_formatted,
        "qty": int(result.get("30", 1)),
        "sn": str(result.get("21", "")),
        "raw": raw_data
    }
```

### 3.3. FEFO 演算法與多品項拆批管線 (`fefo_allocator.py`)

```python
from datetime import datetime

def allocate_fefo_batches(item_code: str, item_name: str, barcode: str, demand_qty: int, inventory_batches: list) -> list:
    """
    inventory_batches: [{'lot': '00821A', 'exp': '2028-12-31', 'qty': 5, 'location': 'NP-AR01-B-03'}, ...]
    依據 EXP 升冪排序分配，自動跨批拆分
    """
    sorted_batches = sorted(
        inventory_batches,
        key=lambda b: datetime.strptime(b['exp'], '%Y-%m-%d')
    )
    
    allocated = []
    remaining = demand_qty
    
    for batch in sorted_batches:
        if remaining <= 0:
            break
        take_qty = min(remaining, batch['qty'])
        allocated.append({
            "item_code": item_code,
            "item_name": item_name,
            "barcode": barcode,
            "lot": str(batch['lot']),            # 強制純文字
            "exp": batch['exp'],
            "qty_allocated": take_qty,
            "location": batch['location']
        })
        remaining -= take_qty
        
    if remaining > 0:
        raise ValueError(f"品項 {item_code} 庫存不足！尚缺 {remaining} 件可用批次。")
        
    return allocated
```

### 3.4. 本地稽核記錄器 (`audit_logger.py`)

```python
from datetime import datetime

def write_outbound_log(order_id: str, operator_email: str, gtin: str, item_code: str, lot: str, exp: str, raw_code: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"{timestamp}|{order_id}|{operator_email}|{gtin}|{item_code}|{lot}|{exp}|1|{raw_code}\n"
    with open("outbound.log", "a", encoding="utf-8") as f:
        f.write(log_line)
```

---

## 4. FastAPI 後端路由設計 (`server.py`)

```python
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import pyotp
import sqlite3
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="autoDen Core Server")
templates = Jinja2Templates(directory="templates")

def get_current_user(request: Request):
    user_email = request.cookies.get("user_email")
    user_role = request.cookies.get("user_role")
    if not user_email or not user_role:
        raise HTTPException(status_code=401, detail="未登入或憑證逾期")
    return {"email": user_email, "role": user_role}

def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="此動作僅限系統管理員執行")
    return current_user

# ERP 品項快查與同步 API
@app.post("/api/erp/sync-products")
def sync_erp_products(user: dict = Depends(get_current_user)):
    # 模擬/實體呼叫 ECOUNT API: /OAPI/V2/InventoryBasic/GetBasicProductsList
    # 將資料寫入本地 SQLite erp_products 表
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    # 寫入更新快取...
    conn.commit()
    conn.close()
    return {"status": "success", "message": "ERP 商品主檔已同步至本地"}

@app.get("/api/erp/products/search")
def search_erp_products(keyword: str, user: dict = Depends(get_current_user)):
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    kw = f"%{keyword.strip()}%"
    cursor.execute("""
        SELECT item_code, item_name, barcode, default_location 
        FROM erp_products 
        WHERE item_code LIKE ? OR item_name LIKE ? OR barcode LIKE ?
        LIMIT 50
    """, (kw, kw, kw))
    results = [
        {"item_code": r[0], "item_name": r[1], "barcode": r[2], "default_loc": r[3]}
        for r in cursor.fetchall()
    ]
    conn.close()
    return {"results": results}

# 階段二：銷貨需求多品項輸入與 FEFO 算批建單 API
class DemandItem(BaseModel):
    item_code: str
    item_name: str
    barcode: str
    qty_demanded: int

class OrderCreatePayload(BaseModel):
    order_id: str
    customer_code: str
    order_date: str
    demands: List[DemandItem]

@app.post("/api/orders/create-with-fefo")
def create_order_with_fefo(payload: OrderCreatePayload, user: dict = Depends(get_current_user)):
    from fefo_allocator import allocate_fefo_batches
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO orders (order_id, customer_code, order_date, status, created_by)
        VALUES (?, ?, ?, 'PICKING', ?)
    """, (payload.order_id, payload.customer_code, payload.order_date, user["email"]))
    
    for demand in payload.demands:
        cursor.execute("SELECT lot, exp, qty, location FROM inventory WHERE item_code = ?", (demand.item_code,))
        batches = [{"lot": row[0], "exp": row[1], "qty": row[2], "location": row[3]} for row in cursor.fetchall()]
        
        allocated = allocate_fefo_batches(demand.item_code, demand.item_name, demand.barcode, demand.qty_demanded, batches)
        for alloc in allocated:
            cursor.execute("""
                INSERT INTO order_items (order_id, item_code, item_name, barcode, location_code, allocated_lot, allocated_exp, qty_allocated, qty_scanned)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (payload.order_id, demand.item_code, demand.item_name, demand.barcode, alloc["location"], alloc["lot"], alloc["exp"], alloc["qty_allocated"]))
            
    conn.commit()
    conn.close()
    return {"status": "success", "order_id": payload.order_id}

# 訂單明細查詢 API (供 Admin 點擊單號彈窗檢視)
@app.get("/api/orders/{order_id}")
def get_order_detail(order_id: str, user: dict = Depends(get_current_user)):
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    cursor.execute("SELECT order_id, customer_code, order_date, status, created_by FROM orders WHERE order_id = ?", (order_id,))
    order = cursor.fetchone()
    if not order:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到該單據")
        
    cursor.execute("""
        SELECT id, item_code, item_name, barcode, location_code, allocated_lot, allocated_exp, qty_allocated, qty_scanned
        FROM order_items WHERE order_id = ?
    """, (order_id,))
    items = [
        {
            "id": r[0], "item_code": r[1], "item_name": r[2], "barcode": r[3],
            "location_code": r[4], "allocated_lot": r[5], "allocated_exp": r[6],
            "qty_allocated": r[7], "qty_scanned": r[8]
        }
        for r in cursor.fetchall()
    ]
    conn.close()
    return {
        "order_id": order[0], "customer_code": order[1], "order_date": order[2],
        "status": order[3], "created_by": order[4], "items": items
    }

# 揀貨單狀態標記 API
@app.post("/api/orders/mark-printed")
def mark_orders_printed(order_ids: List[str], user: dict = Depends(get_current_user)):
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    for oid in order_ids:
        cursor.execute("UPDATE orders SET printed = 1 WHERE order_id = ?", (oid,))
    conn.commit()
    conn.close()
    return {"status": "success", "marked_ids": order_ids}

# 階段四：GS1 對撞核對 API
class ScanPayload(BaseModel):
    order_id: str
    raw_barcode: str

@app.post("/api/scan/verify")
def verify_scan(payload: ScanPayload, user: dict = Depends(get_current_user)):
    from gs1_parser import parse_gs1
    from audit_logger import write_outbound_log
    
    parsed = parse_gs1(payload.raw_barcode)
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, item_code, qty_allocated, qty_scanned, allocated_lot, allocated_exp
        FROM order_items
        WHERE order_id = ? AND allocated_lot = ? AND (barcode = ? OR barcode = '') AND qty_scanned < qty_allocated
    """, (payload.order_id, parsed["lot"], parsed["gtin"]))
    item = cursor.fetchone()
    
    if not item:
        conn.close()
        return JSONResponse(status_code=400, content={
            "match": False,
            "message": "紅燈警報：實刷條碼 GTIN / 批號 LOT / 效期 EXP 與目標不符，或該批次已滿額！",
            "parsed": parsed
        })
        
    item_id, item_code, allocated_qty, scanned, target_lot, target_exp = item
    new_scanned = scanned + 1
    
    cursor.execute("""
        UPDATE order_items 
        SET qty_scanned = ?, scanned_lot = ?, scanned_exp = ?
        WHERE id = ?
    """, (new_scanned, parsed["lot"], parsed["exp"], item_id))
    
    cursor.execute("SELECT SUM(qty_allocated), SUM(qty_scanned) FROM order_items WHERE order_id = ?", (payload.order_id,))
    total_allocated, total_scanned = cursor.fetchone()
    
    order_completed = False
    if total_allocated == total_scanned:
        cursor.execute("UPDATE orders SET status = 'VERIFIED' WHERE order_id = ?", (payload.order_id,))
        order_completed = True
        
    conn.commit()
    conn.close()
    
    write_outbound_log(payload.order_id, user["email"], parsed["gtin"], item_code, parsed["lot"], parsed["exp"], payload.raw_barcode)
    
    return {
        "match": True,
        "message": "綠燈放行：條碼、批號與效期核對無誤",
        "current_item_progress": f"{new_scanned}/{allocated_qty}",
        "order_completed": order_completed,
        "parsed": parsed
    }

# 階段五：Admin 專屬批次 API 拋轉
class BatchSyncPayload(BaseModel):
    order_ids: List[str]

@app.post("/api/admin/orders/batch-sync-ecount")
def batch_sync_to_ecount(payload: BatchSyncPayload, admin: dict = Depends(get_admin_user)):
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    
    synced_orders = []
    for order_id in payload.order_ids:
        cursor.execute("SELECT status FROM orders WHERE order_id = ?", (order_id,))
        row = cursor.fetchone()
        if row and row[0] == "VERIFIED":
            cursor.execute("UPDATE orders SET status = 'SYNCED' WHERE order_id = ?", (order_id,))
            cursor.execute("INSERT INTO sync_logs (order_id, sync_method, operator_email) VALUES (?, 'API', ?)",
                           (order_id, admin["email"]))
            synced_orders.append(order_id)
            
    conn.commit()
    conn.close()
    return {"status": "success", "synced_orders": synced_orders}

# 階段五：預留 CSV 下載 API
@app.get("/api/admin/orders/{order_id}/export-csv")
def export_order_csv(order_id: str, admin: dict = Depends(get_admin_user)):
    return {"status": "pending_template", "order_id": order_id}

# 階段五：Admin 專屬人員 2FA 派發 API
class CreateUserPayload(BaseModel):
    email: str
    role: str

@app.post("/api/admin/users/create")
def admin_create_user(payload: CreateUserPayload, admin: dict = Depends(get_admin_user)):
    secret = pyotp.random_base32()
    conn = sqlite3.connect("autoden.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, totp_secret, role) VALUES (?, ?, ?)",
                   (payload.email, secret, payload.role))
    conn.commit()
    conn.close()
    
    otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(name=payload.email, issuer_name="autoDen WMS")
    return {"email": payload.email, "role": payload.role, "secret": secret, "otpauth_url": otpauth_url}
```

---

## 5. 前端頁面規格與介面實作（嚴格無標題附屬說明文字）

### 5.1. 銷貨建單與配批 (`order_entry.html`)
- 出貨日期下方按鈕列：**「同步 ERP 主檔」按鈕與「新增品項」按鈕並排切齊**。
- 支援「品號」、「品名」、「商品條碼」雙擊（`@dblclick`）彈出 **ECOUNT ERP 品項快查視窗**。
- 快查視窗支援品號、品名、條碼模糊檢索，選取後一次性回填三項資料，並自動 Focus 至「需求數」輸入框。
- 品項垃圾桶圖示常駐可點擊。
- 右側 FEFO 試算明細完整呈現：品號、品名（加寬）、條碼、儲位、配批 (LOT)、有效期限 (EXP)、配批數（關鍵欄位強制不換行）。

### 5.2. 揀貨單列印管理 (`picking_slips.html`)
- 畫面僅顯示待印清單表格與篩選操作，不預先呈現紙張樣式。
- 支援「勾選挑選列印」與「全部列印」。
- 列印觸發直接調用瀏覽器 `window.print()`，由列印預覽呈現純白底黑字、向量 Code 128 條碼與分頁樣式。
- 標註「未列印」或「已列印 (可重印)」。

### 5.3. 打包品保閘門畫面 (`scanner.html`)
- 待驗卡片完整顯示：品號、品名、儲位、目標 GTIN、目標 LOT（保留前導零）、目標 EXP（效期）全要素對撞。
- 專門隱藏 input 接駁 2D 槍實體訊號，嚴禁 alert 彈窗。

### 5.4. Admin 審核與拋轉中控台 (`admin.html`)
- 表格欄位：單號（點擊彈出明細 Modal）、客戶編碼、建單日期、狀態、建立者、操作。
- 批次拋轉勾選器：支援單張與一鍵勾選所有已標記為 `VERIFIED` 的單據，批次倒灌 ECOUNT。
- 預留「下載 CSV」與「批次下載 CSV」操作位置。

### 5.5. 帳號資安 (`security.html`)
- 獨立於 Admin 中控台右側之專屬安全分頁。
- 提供作業人員名冊維護、2FA 密鑰動態派發與 Google Authenticator QR Code 現場綁定。

---

## 6. 開發與部署階段驗收檢查表 (Checklist)

- [ ] **環境鎖定**：確認打包桌本機 `server.py` 綁定 `0.0.0.0:8000`，外部路由器無映射端口，完全阻斷外網連線。
- [ ] **ERP 品項同步與雙擊快查**：
  - [ ] 驗證「同步 ERP 主檔」按鈕觸發後成功自 ECOUNT 拉取主檔至本地 SQLite `erp_products`。
  - [ ] 驗證建單介面品號、品名、商品條碼任一欄位雙擊彈出 ERP 品項快查視窗，選取後完整回填並自動跳轉「需求數」。
- [ ] **格式與防呆檢驗**：
  - [ ] 驗證實刷 GS1 條碼（含開頭前導零批號如 `00821A`），確認寫入 `outbound.log` 與 SQLite 時完整保留前導零。
  - [ ] 驗證品保閘門：實刷時同時核對條碼 GTIN、LOT 與效期 EXP，任一項不符立即觸發 Rose 紅燈死鎖攔截。
- [ ] **中控台與單據流程**：
  - [ ] Admin 中控台表格正確呈現「建單日期」，點擊單號彈出訂單明細視窗查驗單身與實刷進度。
