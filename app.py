import streamlit as st
import pickle
import sklearn
import pandas as pd 
import numpy as np 




st.set_page_config(page_title="Security Predictor", page_icon="🚨")

# 2. Animated Background CSS
def add_bg_animation():
    st.markdown(
        """
        <style>
        /* This targets the main container */
        [data-testid="stAppViewContainer"] {
            background: linear-gradient(132deg, #0f1739, #055eba, #00c7fa);
            background-size: 400% 400%;
            animation: GradientAnimation 15s ease infinite;
        }

        /* The animation movement */
        @keyframes GradientAnimation {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        /* Making text more readable against dark background */
        h1, h2, h3, p, label, button p {
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

pct_size = st.number_input("Enter PacketSize")
trans_rate = st.number_input("Enter Transmission Rate:")
lat = st.number_input("Enter Latency:")
prot = st.number_input("Enter Protocol Type:")
active = st.number_input("Enter number of Active Connections:")
cpu = st.number_input("CPU Usage:")
mem = st.number_input("Memory Usage:")
band = st.number_input("Enter Bandwidth:")
res = st.number_input("Enter Response Time:")
auth_fail = st.number_input("Enter number of auth fails:")
acc = st.number_input("Enter number of access violations:")
fire = st.number_input("Enter number of Firewall Blocks:")
ids = st.number_input("Enter number of Alerts:")
dwt = st.number_input("Enter frequency(DWT):")

st.markdown("---")

if st.button("🔍 SCAN NETWORK FOR ANOMALIES !!"):

    with st.spinner('Analyzing packets and traffic patterns...'):
        # Small delay to make the "scan" feel real
        import time
        time.sleep(1.5)

    input_df = pd.DataFrame([
        {
            'Packet_Size': pct_size,
            'Transmission_Rate': trans_rate,
            'Latency': lat,
            'Protocol_Type': prot,
            'Active_Connections':active,
            'CPU_Usage': cpu,
            'Memory_Usage': mem, 
            'Bandwidth_Utilization': band,
            'Request_Response_Time': res,
            'Auth_Failures': auth_fail,
            'Access_Violations': acc,
            'Firewall_Blocks': fire,
            'IDS_Alerts': ids,
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