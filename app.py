import streamlit as st
import paramiko
from pysnmp.hlapi import *
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

# Initialize the app
st.title("Router Predictive Maintenance App")
st.write("This app connects to a router, collects SNMP data, and applies a predictive detection mechanism.")

# Input fields for router SSH connection
ssh_host = st.text_input("Router SSH Host")
ssh_user = st.text_input("SSH Username")
ssh_pass = st.text_input("SSH Password", type="password")

# SNMP settings
snmp_community = st.text_input("SNMP Community String")
snmp_port = st.number_input("SNMP Port", min_value=1, max_value=65535, value=161)

# Button to initiate data collection
if st.button("Connect and Collect SNMP Data"):
    # Step 2: Establish SSH Connection
    st.write("Connecting to router...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_host, username=ssh_user, password=ssh_pass)
        st.success("Connected to the router via SSH.")
    except Exception as e:
        st.error(f"SSH connection failed: {e}")
    
    # Step 3: Collect SNMP Data
    def get_snmp_data(oid):
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(snmp_community),
            UdpTransportTarget((ssh_host, snmp_port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication:
            return None
        else:
            for var_bind in var_binds:
                return var_bind[1]
    
    # Define OIDs for SNMP data collection (adjust to your router’s configuration)
    snmp_oids = {
        "CPU Usage": "1.3.6.1.4.1.9.2.1.56.0",
        "Memory Usage": "1.3.6.1.4.1.9.2.1.57.0",
        "Uptime": "1.3.6.1.2.1.1.3.0",
        "Temperature": "1.3.6.1.4.1.9.2.1.58.0"
    }

    # Collect data
    snmp_data = {}
    for label, oid in snmp_oids.items():
        value = get_snmp_data(oid)
        if value is not None:
            snmp_data[label] = int(value)
    
    # Convert collected data to a DataFrame for easy handling
    if snmp_data:
        df = pd.DataFrame([snmp_data])
        st.write("SNMP Data Collected:", df)
    else:
        st.error("Failed to retrieve SNMP data.")

    # Step 4: Predictive Detection
    if snmp_data:
        st.write("Applying predictive detection...")
        
        # Basic anomaly detection using Isolation Forest
        model = IsolationForest(contamination=0.1)
        
        # Sample data for demonstration - normally, you would use historical data
        sample_data = pd.DataFrame(
            np.random.normal(size=(100, len(snmp_data.keys()))),
            columns=snmp_data.keys()
        )
        sample_data = pd.concat([sample_data, df], ignore_index=True)

        # Train model
        model.fit(sample_data.drop(index=sample_data.index[-1]))  # Train without the current point
        prediction = model.predict(sample_data.iloc[[-1]])  # Predict on current data point

        if prediction[0] == -1:
            st.warning("Potential fault detected in router!")
            st.write("Reasons:")
            for key, value in snmp_data.items():
                st.write(f"{key}: {value}")
        else:
            st.success("Router is functioning normally.")

# Streamlit's placeholder ensures UI responds dynamically
