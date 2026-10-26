
import ipaddress
import re
from urllib.parse import urlsplit

import streamlit as st

st.set_page_config(
    page_title="LinkGuard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ LinkGuard")
st.subheader("Explainable URL Risk Assessment")
st.write("ระบบวิเคราะห์สัญญาณความเสี่ยงของ URL ด้วยกฎที่อธิบายได้")

st.info(
    "ระบบตรวจสอบข้อความ URL เท่านั้น ไม่เปิดเว็บไซต์ปลายทาง "
    "และไม่สามารถยืนยันความปลอดภัยได้ 100%"
)


def analyze_url(raw_url):
    url = raw_url.strip()
    rules = []
    score = 0

    if not url:
        return {
            "valid": False,
            "score": 0,
            "level": "ข้อมูลไม่เพียงพอ",
            "host": "-",
            "rules": [],
            "message": "กรุณากรอก URL ก่อนวิเคราะห์",
        }

    if any(ch.isspace() for ch in url):
        return {
            "valid": False,
            "score": 0,
            "level": "ข้อมูลไม่เพียงพอ",
            "host": "-",
            "rules": [],
            "message": "URL มีช่องว่าง โปรดตรวจสอบรูปแบบ",
        }

    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = parts.hostname

        if scheme not in ("http", "https") or not host:
            return {
                "valid": False,
                "score": 0,
                "level": "ข้อมูลไม่เพียงพอ",
                "host": "-",
                "rules": [],
                "message": (
                    "URL ไม่ครบ กรุณาใส่ http:// หรือ https:// "
                    "และชื่อโฮสต์"
                ),
            }

        def add_rule(name, points, detected, reason):
            nonlocal score
            awarded = points if detected else 0
            score += awarded

            rules.append({
                "กฎที่ตรวจสอบ": name,
                "ผลตรวจ": "ตรวจพบ" if detected else "ไม่พบ",
                "คะแนน": awarded,
                "เหตุผล": reason if detected else "-",
            })

        # กฎ 1: มี @ ในส่วนชื่อโฮสต์
        add_rule(
            "มี @ ในส่วนชื่อโฮสต์",
            3,
            "@" in parts.netloc,
            "อาจทำให้เข้าใจผิดว่าโฮสต์จริงเป็นโดเมนอื่น",
        )

        # กฎ 2: โฮสต์เป็น IP address
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        add_rule(
            "โฮสต์เป็น IP address",
            2,
            is_ip,
            "ควรตรวจสอบแหล่งที่มาของโฮสต์เพิ่มเติม",
        )

        # กฎ 3: ใช้ HTTP
        add_rule(
            "ใช้ HTTP",
            1,
            scheme == "http",
            "HTTP ไม่มีการเข้ารหัส TLS ในการเชื่อมต่อ",
        )

        # กฎ 4: พบ Punycode ในชื่อโฮสต์
        punycode = any(
            label.lower().startswith("xn--")
            for label in host.split(".")
        )

        add_rule(
            "พบรูปแบบ Punycode",
            2,
            punycode,
            "ควรตรวจสอบชื่อโดเมนและตัวอักษรที่ใช้",
        )

        # กฎ 5: ชื่อโฮสต์มีหลายระดับ
        many_levels = len(host.split(".")) >= 5

        add_rule(
            "โฮสต์มีหลายระดับ",
            1,
            many_levels,
            "ควรตรวจสอบโครงสร้างและโดเมนหลัก",
        )

        # กฎ 6: พบคำที่ควรตรวจสอบเพิ่มเติม
        suspicious_words = {
            "login", "verify", "update", "secure",
            "account", "password", "confirm",
        }

        components = re.split(r"[^a-zA-Z0-9]+", url.lower())
        matches = sorted(suspicious_words.intersection(components))

        add_rule(
            "พบคำเกี่ยวกับการเข้าสู่ระบบ",
            1,
            bool(matches),
            "พบคำ: " + ", ".join(matches),
        )

        # คะแนนดิบสูงสุดจากกฎทั้งหมดคือ 10
        score = min(score, 10)

        if score >= 6:
            level = "ควรระวังสูง"
        elif score >= 3:
            level = "ควรตรวจสอบเพิ่มเติม"
        else:
            level = "พบสัญญาณตามกฎน้อย"

        detected_count = sum(
            1 for rule in rules
            if rule["ผลตรวจ"] == "ตรวจพบ"
        )

        return {
            "valid": True,
            "score": score,
            "level": level,
            "host": host,
            "rules": rules,
            "message": f"ตรวจพบสัญญาณตามกฎ {detected_count} รายการ",
        }

    except (ValueError, UnicodeError):
        return {
            "valid": False,
            "score": 0,
            "level": "ข้อมูลไม่เพียงพอ",
            "host": "-",
            "rules": [],
            "message": "ไม่สามารถแยกส่วน URL ได้",
        }


url = st.text_input(
    "URL ที่ต้องการวิเคราะห์",
    placeholder="https://example.com",
)

if st.button("🔎 วิเคราะห์ URL", type="primary"):
    result = analyze_url(url)

    st.divider()

    if not result["valid"]:
        st.warning(result["message"])
    else:
        col1, col2, col3 = st.columns(3)

        col1.metric("คะแนนตามกฎ", f'{result["score"]}/10')
        col2.metric("ระดับผลประเมิน", result["level"])
        col3.metric("โฮสต์", result["host"])

        st.write(result["message"])
        st.subheader("📋 รายละเอียดคะแนนแต่ละกฎ")

        st.dataframe(
            result["rules"],
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("💡 เหตุผลที่ตรวจพบ")

        detected = [
            rule for rule in result["rules"]
            if rule["ผลตรวจ"] == "ตรวจพบ"
        ]

        if detected:
            for rule in detected:
                st.write(
                    f'- **{rule["กฎที่ตรวจสอบ"]}** '
                    f'+{rule["คะแนน"]} คะแนน — {rule["เหตุผล"]}'
                )
        else:
            st.success(
                "ไม่พบสัญญาณตามกฎที่กำหนด "
                "แต่ไม่ได้ยืนยันว่า URL ปลอดภัย"
            )

        st.warning(
            "คะแนนนี้เป็นระบบกฎเบื้องต้น ไม่ใช่ความน่าจะเป็น "
            "และอาจแจ้งเตือนเว็บไซต์ปกติได้"
        )
