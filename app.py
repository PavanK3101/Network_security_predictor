import streamlit as st
import pickle
import sklearn
import pandas as pd 
import numpy as np 




st.set_page_config(page_title="Security Predictor", page_icon="🚨", layout = "wide")

# 2. Animated Background CSS
def add_bg_animation():
    st.markdown(
        """
        <style>
        /* This targets the main container */
        [data-testid="stHeadingWithActionElements"] {
            color : #ffffff !important;
        }

        [data-testid="stAppViewContainer"] {
            background-image: linear-gradient(to right bottom, #0f1739, #00c7fa);
            background-size: 100% 100%;
            background-attachment: fixed;
            margin:0;
        }

        /* The animation movement */
        @keyframes GradientAnimation {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        /* Making text more readable against dark background */
        h1, h2, h3, h4, p, label, button p {
            color: #ffffff !important;
        }

        .stButton>button p {
            color: #000000 !important; 
        }
        
        stButton>button {
            background: linear-gradient(90deg, #00f2fe 0%, #4facfe 100%);
            color: black;
            font-weight: bold;
            border: none;
            border-radius: 5px;
            height: 3em;
            width: 100%;
            transition: all 0.3s ease-in-out;
        }
        .stButton>button:hover {
            box-shadow: 0px 0px 20px 5px rgba(79, 172, 254, 0.8);
            transform: translateY(-2px);
        }

        .stButton>button p:hover {
            color: #ffffff !important; 
        }

        </style>
        """,
        unsafe_allow_html=True
    )

add_bg_animation()


with open("proj1.pkl", 'rb') as f:
    dec = pickle.load(f)

with open("scaler.pkl", 'rb') as f:
    sc = pickle.load(f)

st.title("🚨 Network Anomaly Detection")

st.write("Companies need ML that can flag intrusions, DDoS, and abnormal loads; this model is designed exactly for load prediction + anomaly detection in security contexts.")

st.subheader("📊 System Metrics")

st.markdown('---')

# Creating 4 columns for a compact, technical view
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("#### 📡 Traffic")
    p_size = st.number_input("Enter Packet Size", value=500.0, step=1.0)
    t_rate = st.number_input("Enter Transmission Rate", value=50.0)
    lat = st.number_input("Enter Latency", value=20.0)
    prot = st.selectbox("Enter Protocol Type", options=[0, 1, 2, 3])

with col2:
    st.markdown("#### ⚡ Hardware")
    cpu = st.number_input("Enter CPU %", value=15.0, max_value=100000.0)
    mem = st.number_input("Enter Mem %", value=30.0, max_value=100000.0)
    active = st.number_input("Enter number of Active Connections", value=10, step=1)
    band = st.number_input("Enter Bandwidth", value=100.0)

with col3:
    st.markdown("#### 🛡️ Security")
    # Setting this to exactly 9 as per your request to see the effect
    auth_fail = st.number_input("Enter number of auth fails", value=9, step=1)
    acc_viol = st.number_input("Enter number of access violations", value=0, step=1)
    f_blocks = st.number_input("Enter number of Firewall Blocks", value=0, step=1)
    ids_alt = st.number_input("Enter number of IDS Alerts", value=0, step=1)

with col4:
    st.markdown("#### ⏱️ Other")
    res_time = st.number_input("Enter Response Time", value=0.01)
    dwt = st.number_input("Enter frequency(DWT)", value=0.0)


st.markdown("---")

if st.button("🔍 SCAN NETWORK FOR ANOMALIES !!"):

    with st.spinner('Analyzing packets and traffic patterns...'):
        # Small delay to make the "scan" feel real
        import time
        time.sleep(1.5)

    input_df = pd.DataFrame([
        {
            'Packet_Size': p_size,
            'Transmission_Rate': t_rate,
            'Latency': lat,
            'Protocol_Type': prot,
            'Active_Connections':active,
            'CPU_Usage': cpu,
            'Memory_Usage': mem, 
            'Bandwidth_Utilization': band,
            'Request_Response_Time': res_time,
            'Auth_Failures': auth_fail,
            'Access_Violations': acc_viol,
            'Firewall_Blocks': f_blocks,
            'IDS_Alerts': ids_alt,
            'DWT_Feature_1': dwt
        }
    ])

    test = sc.transform(input_df)

    result = dec.predict(test)[0]

    st.subheader("Prediction Result")
    if result == 1:
        st.error(f"⚠️ **Anomalous Load Detected!**")
        st.metric(label="Risk Level", value="HIGH", delta=f"{result:.1f}% Probability")
        st.warning("Action Required: Check firewall logs and active connections.")
    else:
        st.success(f"✅ **System Operating Normally**")
        st.metric(label="Risk Level", value="LOW", delta=f"{result:.1f}% Probability", delta_color="inverse")



