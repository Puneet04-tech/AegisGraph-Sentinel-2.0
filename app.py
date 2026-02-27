"""
AegisGraph Sentinel 2.0 - Streamlit Web Application
Real-time Fraud Detection Interface
"""

import streamlit as st
import requests
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time

# Page configuration
st.set_page_config(
    page_title="AegisGraph Sentinel 2.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API Configuration
API_URL = "http://localhost:8000"

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        padding: 20px;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .stAlert {
        border-radius: 10px;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    </style>
""", unsafe_allow_html=True)

# Title
st.markdown('<h1 class="main-header">🛡️ AegisGraph Sentinel 2.0</h1>', unsafe_allow_html=True)
st.markdown('<p style="text-align: center; font-size: 1.2rem; color: #666;">Real-Time Cross-Channel Mule Account Detection & Neutralization</p>', unsafe_allow_html=True)
st.markdown("---")

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=100)
    st.title("Navigation")
    page = st.radio("Select Page", [
        "🏠 Dashboard",
        "🔍 Single Transaction Check",
        "📊 Batch Processing",
        "📈 Statistics & Analytics",
        "ℹ️ About System"
    ])
    
    st.markdown("---")
    
    # API Status Check
    try:
        response = requests.get(f"{API_URL}/health", timeout=2)
        if response.status_code == 200:
            health = response.json()
            st.success("✅ API Online")
            st.metric("Uptime", f"{int(health.get('uptime_seconds', 0))}s")
            mode = "🎭 DEMO MODE" if not health.get('model_loaded', False) else "🚀 PRODUCTION"
            st.info(mode)
        else:
            st.error("⚠️ API Issue")
    except:
        st.error("❌ API Offline")
        st.warning("Start API: `python -m uvicorn src.api.main:app --reload`")

# Page: Dashboard
if page == "🏠 Dashboard":
    st.header("📊 Real-Time Dashboard")
    
    col1, col2, col3, col4 = st.columns(4)
    
    try:
        response = requests.get(f"{API_URL}/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            total_requests = stats.get('total_requests', 0)
            decisions = stats.get('decisions', {})
            flagged = decisions.get('REVIEW', 0) + decisions.get('BLOCK', 0)
            
            with col1:
                st.metric("Total Checks", total_requests, delta="Live")
            with col2:
                flag_rate = (flagged / max(total_requests, 1)) * 100
                st.metric("Flagged", flagged, delta=f"{flag_rate:.1f}%")
            with col3:
                st.metric("Avg Response", f"{stats.get('avg_processing_time_ms', 0):.1f}ms", delta="Fast")
            with col4:
                uptime_hours = stats.get('uptime_seconds', 0) / 3600
                st.metric("Uptime", f"{uptime_hours:.1f}h", delta="Stable")
            
            # Quick Test Section
            st.markdown("---")
            st.subheader("⚡ Quick Transaction Test")
            
            cols = st.columns([2, 1, 1])
            with cols[0]:
                quick_amount = st.number_input("Amount (₹)", min_value=1.0, max_value=1000000.0, value=5000.0, step=100.0)
            with cols[1]:
                quick_mode = st.selectbox("Mode", ["UPI", "IMPS", "NEFT", "RTGS"])
            with cols[2]:
                st.write("")
                st.write("")
                if st.button("🔍 Check Now", use_container_width=True):
                    with st.spinner("Analyzing..."):
                        txn = {
                            "transaction_id": f"QUICK_{int(time.time())}",
                            "source_account": "quick_test_user",
                            "target_account": "test_merchant",
                            "amount": quick_amount,
                            "currency": "INR",
                            "mode": quick_mode,
                            "timestamp": datetime.utcnow().isoformat() + "Z"
                        }
                        
                        try:
                            response = requests.post(f"{API_URL}/api/v1/fraud/check", json=txn, timeout=10)
                            response.raise_for_status()
                            result = response.json()
                            
                            risk_score = result.get('risk_score', 0)
                            decision = result.get('decision', 'UNKNOWN')
                            
                            # Display result
                            st.markdown("---")
                            col_a, col_b, col_c = st.columns(3)
                            
                            with col_a:
                                st.metric("Risk Score", f"{risk_score:.3f}")
                            with col_b:
                                color = "🟢" if decision == "ALLOW" else "🟡" if decision == "REVIEW" else "🔴"
                                st.metric("Decision", f"{color} {decision}")
                            with col_c:
                                st.metric("Confidence", f"{(1 - abs(risk_score - 0.5) * 2) * 100:.1f}%")
                            
                            # Risk Gauge
                            fig = go.Figure(go.Indicator(
                                mode="gauge+number+delta",
                                value=risk_score * 100,
                                domain={'x': [0, 1], 'y': [0, 1]},
                                title={'text': "Risk Level", 'font': {'size': 24}},
                                delta={'reference': 50, 'increasing': {'color': "red"}},
                                gauge={
                                    'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                                    'bar': {'color': "darkblue"},
                                    'bgcolor': "white",
                                    'borderwidth': 2,
                                    'bordercolor': "gray",
                                    'steps': [
                                        {'range': [0, 40], 'color': '#90EE90'},
                                        {'range': [40, 70], 'color': '#FFD700'},
                                        {'range': [70, 100], 'color': '#FF6B6B'}
                                    ],
                                    'threshold': {
                                        'line': {'color': "red", 'width': 4},
                                        'thickness': 0.75,
                                        'value': 90
                                    }
                                }
                            ))
                            fig.update_layout(height=300)
                            st.plotly_chart(fig, use_container_width=True)
                            
                            # Show risk breakdown
                            if 'risk_breakdown' in result:
                                breakdown = result['risk_breakdown']
                                st.subheader("📊 Risk Breakdown")
                                breakdown_cols = st.columns(len(breakdown))
                                for idx, (component, value) in enumerate(breakdown.items()):
                                    with breakdown_cols[idx]:
                                        st.metric(component.title(), f"{value:.2%}")
                            
                            st.info(f"💡 {result.get('explanation', 'No explanation available')}")
                            
                            # Force refresh to update stats
                            st.success("✅ Transaction analyzed successfully! Stats updated.")
                            time.sleep(0.5)
                            st.rerun()
                            
                        except requests.exceptions.RequestException as e:
                            st.error(f"❌ API Error: {str(e)}")
                        except Exception as e:
                            st.error(f"❌ Error: {str(e)}")
        
        else:
            st.error("Unable to fetch statistics")
    
    except Exception as e:
        st.error(f"Error connecting to API: {e}")

# Page: Single Transaction Check
elif page == "🔍 Single Transaction Check":
    st.header("🔍 Single Transaction Fraud Check")
    
    with st.form("transaction_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Transaction Details")
            txn_id = st.text_input("Transaction ID", value=f"TXN{int(time.time())}")
            source_account = st.text_input("Source Account", value="ACC_SOURCE_001")
            target_account = st.text_input("Target Account", value="ACC_TARGET_001")
            amount = st.number_input("Amount (₹)", min_value=0.01, value=10000.0, step=100.0)
            
        with col2:
            st.subheader("Additional Information")
            currency = st.selectbox("Currency", ["INR", "USD", "EUR", "GBP"])
            mode = st.selectbox("Transaction Mode", ["UPI", "IMPS", "NEFT", "RTGS", "Card", "Wallet"])
            device_id = st.text_input("Device ID (Optional)", value="")
            location = st.text_input("Location (Optional)", value="")
        
        st.markdown("---")
        
        # Biometrics (Optional)
        with st.expander("🔑 Add Behavioral Biometrics (Optional)"):
            use_biometrics = st.checkbox("Include keystroke dynamics")
            if use_biometrics:
                st.info("Simulated biometrics will be added")
        
        submit = st.form_submit_button("🔍 Check Transaction", use_container_width=True)
        
        if submit:
            with st.spinner("🔄 Analyzing transaction..."):
                # Prepare request
                transaction = {
                    "transaction_id": txn_id,
                    "source_account": source_account,
                    "target_account": target_account,
                    "amount": float(amount),
                    "currency": currency,
                    "mode": mode,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                
                if device_id:
                    transaction["device_id"] = device_id
                if location:
                    transaction["location"] = location
                
                # Make API call
                try:
                    response = requests.post(f"{API_URL}/api/v1/fraud/check", json=transaction, timeout=10)
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        st.success("✅ Analysis Complete!")
                        
                        # Results Display
                        st.markdown("---")
                        st.subheader("📊 Analysis Results")
                        
                        # Top Metrics
                        metric_cols = st.columns(4)
                        with metric_cols[0]:
                            risk = result['risk_score']
                            st.metric("Risk Score", f"{risk:.3f}", delta=f"{(risk-0.5):.3f}")
                        with metric_cols[1]:
                            decision = result['decision']
                            emoji = "🟢" if decision == "ALLOW" else "🟡" if decision == "REVIEW" else "🔴"
                            st.metric("Decision", f"{emoji} {decision}")
                        with metric_cols[2]:
                            st.metric("Confidence", f"{result['confidence']:.1%}")
                        with metric_cols[3]:
                            st.metric("Processing Time", f"{result['processing_time_ms']:.1f}ms")
                        
                        # Risk Breakdown
                        st.markdown("---")
                        st.subheader("📈 Risk Component Breakdown")
                        
                        breakdown = result['breakdown']
                        df = pd.DataFrame({
                            'Component': ['Graph Risk', 'Velocity Risk', 'Behavioral Risk', 'Entropy Risk'],
                            'Score': [breakdown['graph'], breakdown['velocity'], breakdown['behavior'], breakdown['entropy']]
                        })
                        
                        col_chart, col_table = st.columns([2, 1])
                        
                        with col_chart:
                            fig = px.bar(df, x='Component', y='Score', 
                                        title='Risk Factors',
                                        color='Score',
                                        color_continuous_scale='RdYlGn_r')
                            fig.update_layout(height=400)
                            st.plotly_chart(fig, use_container_width=True)
                        
                        with col_table:
                            st.dataframe(df.style.background_gradient(cmap='RdYlGn_r', subset=['Score']), 
                                       use_container_width=True, height=400)
                        
                        # Explanation
                        st.markdown("---")
                        st.subheader("💡 Explanation")
                        
                        if decision == "BLOCK":
                            st.error(result['explanation'])
                        elif decision == "REVIEW":
                            st.warning(result['explanation'])
                        else:
                            st.success(result['explanation'])
                        
                        st.info(f"🎯 **Recommended Action:** {result['recommended_action']}")
                        
                        # JSON Response
                        with st.expander("🔍 View Full JSON Response"):
                            st.json(result)
                    
                    else:
                        st.error(f"Error: {response.status_code}")
                        st.json(response.json())
                
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
                    st.info("Make sure the API server is running: `python -m uvicorn src.api.main:app --reload`")

# Page: Batch Processing
elif page == "📊 Batch Processing":
    st.header("📊 Batch Transaction Processing")
    
    st.info("💡 Process multiple transactions at once for bulk fraud detection")
    
    # File Upload
    uploaded_file = st.file_uploader("Upload CSV file with transactions", type=['csv'])
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ Loaded {len(df)} transactions")
            
            st.subheader("Preview")
            st.dataframe(df.head(10), use_container_width=True)
            
            if st.button("🚀 Process All Transactions", use_container_width=True):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                results = []
                
                for idx, row in df.iterrows():
                    status_text.text(f"Processing {idx+1}/{len(df)}...")
                    
                    txn = {
                        "transaction_id": str(row.get('transaction_id', f'TXN_{idx}')),
                        "source_account": str(row.get('source_account', 'unknown')),
                        "target_account": str(row.get('target_account', 'unknown')),
                        "amount": float(row.get('amount', 0)),
                        "currency": str(row.get('currency', 'INR')),
                        "mode": str(row.get('mode', 'UPI')),
                        "timestamp": str(row.get('timestamp', datetime.utcnow().isoformat() + "Z"))
                    }
                    
                    # Add optional fields if present in CSV
                    if 'ip_address' in row and pd.notna(row['ip_address']):
                        txn['ip_address'] = str(row['ip_address'])
                    if 'device_id' in row and pd.notna(row['device_id']):
                        txn['device_id'] = str(row['device_id'])
                    if 'location' in row and pd.notna(row['location']):
                        txn['location'] = str(row['location'])
                    
                    try:
                        response = requests.post(f"{API_URL}/api/v1/fraud/check", json=txn, timeout=30)
                        if response.status_code == 200:
                            result = response.json()
                            results.append({
                                'Transaction ID': txn['transaction_id'],
                                'Source': txn['source_account'],
                                'Target': txn['target_account'],
                                'Amount': f"₹{txn['amount']:,.0f}",
                                'Risk Score': f"{result['risk_score']:.2%}",
                                'risk_score_numeric': result['risk_score'],  # For charting
                                'Decision': result['decision'],
                                'Confidence': f"{result['confidence']:.0%}",
                                'Graph Risk': f"{result['breakdown']['graph']:.2%}",
                                'Velocity Risk': f"{result['breakdown']['velocity']:.2%}",
                            })
                        else:
                            st.error(f"API Error for {txn['transaction_id']}: Status {response.status_code}")
                            results.append({
                                'Transaction ID': txn['transaction_id'],
                                'Source': txn['source_account'],
                                'Target': txn['target_account'],
                                'Amount': f"₹{txn['amount']:,.0f}",
                                'Risk Score': 'ERROR',
                                'risk_score_numeric': 0,
                                'Decision': 'ERROR',
                                'Confidence': 'N/A',
                                'Graph Risk': 'N/A',
                                'Velocity Risk': 'N/A',
                            })
                    except Exception as e:
                        st.error(f"Error processing {txn.get('transaction_id', 'unknown')}: {str(e)}")
                        results.append({
                            'Transaction ID': txn.get('transaction_id', 'unknown'),
                            'Source': txn.get('source_account', 'unknown'),
                            'Target': txn.get('target_account', 'unknown'),
                            'Amount': f"₹{txn.get('amount', 0):,.0f}",
                            'Risk Score': 'ERROR',
                            'risk_score_numeric': 0,
                            'Decision': 'ERROR',
                            'Confidence': 'N/A',
                            'Graph Risk': 'N/A',
                            'Velocity Risk': 'N/A',
                        })
                    
                    progress_bar.progress((idx + 1) / len(df))
                
                status_text.text("✅ Processing complete!")
                
                # Results
                st.markdown("---")
                st.subheader("📈 Results Summary")
                
                # Expected results info for sample data
                st.info("""
                **Understanding the Results:**
                - 🟢 **ALLOW**: Low risk (< 40%) - Normal transactions
                - 🟡 **REVIEW**: Medium risk (40-70%) - Suspicious patterns detected, needs analyst review
                - 🔴 **BLOCK**: High risk (≥ 70%) - Multiple fraud indicators, immediate blocking recommended
                
                **Sample data includes:**
                - Known mule accounts from real fraud chains (triggers high graph risk)
                - Late night transactions 2-4 AM (triggers entropy risk)
                - High amounts ≥ ₹100k (triggers velocity risk)
                - Mule-to-mule transfers (triggers multiple risk factors)
                """)
                
                results_df = pd.DataFrame(results)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    blocked = len(results_df[results_df['Decision'] == 'BLOCK'])
                    st.metric("Blocked", blocked, delta=f"{blocked/len(results_df)*100:.1f}%")
                with col2:
                    review = len(results_df[results_df['Decision'] == 'REVIEW'])
                    st.metric("Review", review, delta=f"{review/len(results_df)*100:.1f}%")
                with col3:
                    allowed = len(results_df[results_df['Decision'] == 'ALLOW'])
                    st.metric("Allowed", allowed, delta=f"{allowed/len(results_df)*100:.1f}%")
                
                # Charts
                col_a, col_b = st.columns(2)
                
                with col_a:
                    fig_pie = px.pie(results_df, names='Decision', title='Decision Distribution')
                    st.plotly_chart(fig_pie, use_container_width=True)
                
                with col_b:
                    fig_hist = px.histogram(results_df, x='risk_score_numeric', nbins=20, 
                                          title='Risk Score Distribution',
                                          labels={'risk_score_numeric': 'Risk Score'})
                    st.plotly_chart(fig_hist, use_container_width=True)
                
                # Full Results Table (exclude numeric helper column)
                st.subheader("📋 Detailed Results")
                display_df = results_df.drop(columns=['risk_score_numeric'])
                
                # Highlight flagged transactions
                flagged_df = results_df[results_df['Decision'].isin(['REVIEW', 'BLOCK'])]
                if len(flagged_df) > 0:
                    st.warning(f"⚠️ {len(flagged_df)} transactions flagged for review or blocking")
                    with st.expander("🚨 View Flagged Transactions"):
                        flagged_display = flagged_df.drop(columns=['risk_score_numeric'])
                        st.dataframe(flagged_display, use_container_width=True)
                
                st.dataframe(display_df, use_container_width=True)
                
                # Download Results
                csv = display_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Results CSV",
                    data=csv,
                    file_name=f"fraud_check_results_{int(time.time())}.csv",
                    mime="text/csv"
                )
        
        except Exception as e:
            st.error(f"Error processing file: {e}")
    
    else:
        st.markdown("### Sample CSV Format")
        st.info("💡 **Enhanced test data** with 12 transactions including ALLOW, REVIEW, and BLOCK scenarios")
        st.warning("🔴 **NEW**: Added 2 extreme-risk transactions that will trigger BLOCK decisions (₹250k-300k + mule accounts + late night)")
        
        # Create diverse test data with known mule accounts and various risk patterns
        sample_df = pd.DataFrame({
            'transaction_id': [
                'TXN_TEST_001',  # Normal transaction
                'TXN_TEST_002',  # Normal transaction
                'TXN_TEST_003',  # Normal transaction
                'TXN_TEST_004',  # Normal high amount
                'TXN_TEST_005',  # Known mule account (REVIEW)
                'TXN_TEST_006',  # Known mule account (REVIEW)
                'TXN_TEST_007',  # Mule to mule moderate (REVIEW)
                'TXN_TEST_008',  # Mule late night (REVIEW)
                'TXN_TEST_009',  # 🔴 EXTREME: Mule + 250k + 3AM (BLOCK)
                'TXN_TEST_010',  # 🔴 EXTREME: Mule→Mule + 300k + 2AM (BLOCK)
                'TXN_TEST_011',  # Normal small transaction
                'TXN_TEST_012',  # Normal transaction
            ],
            'source_account': [
                'ACC00000139',    # Normal account (verified non-mule)
                'ACC00000140',    # Normal account (verified non-mule)
                'ACC00000141',    # Normal account (verified non-mule)
                'ACC00000142',    # Normal account (verified non-mule)
                'ACC00001071',    # KNOWN MULE (from fraud chain)
                'ACC00003254',    # KNOWN MULE (from fraud chain)
                'ACC00001071',    # KNOWN MULE
                'ACC00000179',    # KNOWN MULE (from fraud chain)
                'ACC00004766',    # 🔴 EXTREME RISK MULE
                'ACC00001071',    # 🔴 EXTREME RISK MULE to MULE
                'ACC00000145',    # Normal account
                'ACC00000146',    # Normal account
            ],
            'target_account': [
                'MERCHANT_001',   # Merchant
                'ACC00000150',    # Normal P2P
                'MERCHANT_002',   # Merchant
                'MERCHANT_003',   # Merchant (high amount OK)
                'ACC00000150',    # Normal account (but source is mule)
                'ACC00000151',    # Normal account
                'ACC00003254',    # MULE to MULE transaction
                'ACC00000152',    # Normal account
                'ACC00000153',    # 🔴 Normal account (but HUGE amount + late night)
                'ACC00003254',    # 🔴 MULE to MULE + HUGE + LATE NIGHT
                'MERCHANT_004',   # Merchant
                'ACC00000154',    # Normal P2P
            ],
            'amount': [
                2500.00,      # Normal
                15000.00,     # Normal
                8500.00,      # Normal
                95000.00,     # High but legitimate merchant payment
                45000.00,     # Moderate (mule account)
                35000.00,     # Moderate (mule)
                85000.00,     # High (mule to mule)
                40000.00,     # Moderate (mule late night)
                250000.00,    # 🔴 EXTREME amount + mule
                300000.00,    # 🔴 EXTREME amount + mule to mule
                500.00,       # Small
                12000.00,     # Normal
            ],
            'currency': ['INR'] * 12,
            'mode': [
                'UPI',      # Fast payment
                'UPI',      # Fast payment
                'UPI',      # Fast payment
                'NEFT',     # Normal for high amount
                'UPI',      # Fast (suspicious for large with mule)
                'UPI',      # UPI
                'IMPS',     # Immediate (mule to mule)
                'UPI',      # UPI late night
                'IMPS',     # 🔴 IMPS for huge amount (instant transfer)
                'IMPS',     # 🔴 IMPS for huge mule transfer
                'UPI',      # Small UPI
                'UPI',      # UPI
            ],
            'timestamp': [
                '2026-02-26T14:30:00Z',  # Afternoon (normal)
                '2026-02-26T10:15:00Z',  # Morning (normal)
                '2026-02-26T16:00:00Z',  # Afternoon (normal)
                '2026-02-26T11:20:00Z',  # Morning (normal)
                '2026-02-26T18:45:00Z',  # Evening (mule but normal time)
                '2026-02-26T12:30:00Z',  # Afternoon (mule)
                '2026-02-26T22:00:00Z',  # Night (mule to mule)
                '2026-02-26T04:00:00Z',  # LATE NIGHT 4 AM (mule)
                '2026-02-26T03:15:00Z',  # 🔴 3:15 AM + EXTREME amount
                '2026-02-26T02:30:00Z',  # 🔴 2:30 AM + EXTREME mule transfer
                '2026-02-26T19:00:00Z',  # Evening
                '2026-02-26T13:45:00Z',  # Afternoon
            ],
            'ip_address': [
                '103.25.45.67',
                '103.25.45.68',
                '103.25.45.69',
                '103.25.45.70',
                '103.25.45.71',
                '103.25.45.72',
                '192.168.1.100',  # Private IP for mule-to-mule
                '103.25.45.73',
                '192.168.1.101',  # 🔴 Private IP + extreme
                '192.168.1.102',  # 🔴 Private IP + extreme
                '103.25.45.74',
                '103.25.45.75',
            ],
            'device_id': [
                'DEV_' + str(i).zfill(6) for i in range(1, 13)
            ],
            'location': [
                'Mumbai, India',
                'Delhi, India',
                'Bangalore, India',
                'Pune, India',
                'Mumbai, India',
                'Delhi, India',
                'Mumbai, India',
                'Kolkata, India',
                'Mumbai, India',      # 🔴 Same location pattern
                'Mumbai, India',      # 🔴 Same location pattern
                'Chennai, India',
                'Hyderabad, India',
            ]
        })
        
        st.dataframe(sample_df, use_container_width=True)
        
        # Add legend
        st.markdown("""
        **Test Data Legend (12 Transactions):**
        
        **🟢 ALLOW (5 transactions)** - Clean, legitimate transactions:
        - TXN_TEST_001-004, 011-012: Normal accounts, reasonable amounts, business hours
        
        **🟡 REVIEW (5 transactions)** - Suspicious patterns requiring analyst review:
        - TXN_TEST_005-006: Known mule accounts with moderate amounts
        - TXN_TEST_007: Mule-to-mule transfer at night
        - TXN_TEST_008: Mule account at 4 AM
        
        **🔴 BLOCK (2 transactions)** - Extreme risk, immediate blocking:
        - **TXN_TEST_009**: Mule account + ₹250k + 3:15 AM + Private IP = **EXTREME RISK**
        - **TXN_TEST_010**: Mule→Mule + ₹300k + 2:30 AM + IMPS = **CRITICAL FRAUD**
        
        **Risk Factors:**
        - 🚨 **Mule accounts**: ACC00001071, ACC00003254, ACC00000179, ACC00004766
        - 💰 **Extreme amounts**: ₹250k-300k trigger high velocity risk
        - 🌙 **Late night**: 2-4 AM adds entropy risk
        - 🔄 **Mule-to-mule**: Direct transfer between known fraud accounts
        """)
        
        csv = sample_df.to_csv(index=False)
        st.download_button(
            label="📥 Download Sample CSV",
            data=csv,
            file_name="sample_transactions.csv",
            mime="text/csv"
        )

# Page: Statistics
elif page == "📈 Statistics & Analytics":
    st.header("📈 System Statistics & Analytics")
    
    try:
        response = requests.get(f"{API_URL}/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            
            # Top Metrics
            st.subheader("Key Performance Indicators")
            col1, col2, col3, col4 = st.columns(4)
            
            # Extract data
            total_requests = stats.get('total_requests', 0)
            decisions = stats.get('decisions', {})
            flagged = decisions.get('REVIEW', 0) + decisions.get('BLOCK', 0)
            avg_time = stats.get('avg_processing_time_ms', 0)
            uptime = stats.get('uptime_seconds', 0)
            
            with col1:
                st.metric("Total Checks", total_requests)
            with col2:
                st.metric("Flagged", flagged)
            with col3:
                st.metric("Avg Response Time", f"{avg_time:.2f}ms", 
                         delta="Good" if avg_time < 200 else "Slow")
            with col4:
                st.metric("Uptime", f"{uptime/3600:.1f}h")
            
            # System Health
            st.markdown("---")
            st.subheader("🏥 System Health")
            
            health_col1, health_col2 = st.columns(2)
            
            with health_col1:
                # Performance Gauge
                performance_score = min(100, (200 - avg_time) / 200 * 100)
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=performance_score,
                    title={'text': "Performance Score"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 50], 'color': "lightgray"},
                            {'range': [50, 75], 'color': "yellow"},
                            {'range': [75, 100], 'color': "lightgreen"}
                        ],
                    }
                ))
                st.plotly_chart(fig_gauge, use_container_width=True)
            
            with health_col2:
                st.write("")
                st.write("")
                st.write("")
                if avg_time < 100:
                    st.success("🚀 Excellent Performance")
                elif avg_time < 200:
                    st.info("✅ Good Performance")
                else:
                    st.warning("⚠️ Performance Degradation")
                
                flagged_rate = flagged / max(total_requests, 1)
                st.metric("Fraud Detection Rate", f"{flagged_rate*100:.2f}%")
                
                if flagged_rate > 0.1:
                    st.warning("⚠️ High fraud rate detected")
                else:
                    st.success("✅ Normal transaction patterns")
        
        else:
            st.error("Unable to fetch statistics")
    
    except Exception as e:
        st.error(f"Error: {e}")

# Page: About
elif page == "ℹ️ About System":
    st.header("ℹ️ About AegisGraph Sentinel 2.0")
    
    st.markdown("""
    ### 🛡️ Real-Time Cross-Channel Mule Account Detection
    
    **AegisGraph Sentinel 2.0** is an advanced fraud detection system designed for the 2026 National Fraud Prevention Challenge.
    
    #### 🎯 Key Features
    
    - **Heterogeneous Temporal Graph Neural Networks (HTGNN)**: Advanced AI model for detecting complex fraud patterns
    - **Multi-Modal Risk Assessment**: Combines graph topology, transaction velocity, behavioral biometrics, and entropy analysis
    - **Real-Time Processing**: < 200ms response time for instant fraud detection
    - **Explainable AI**: Human-readable explanations for every decision
    - **Batch Processing**: Handle thousands of transactions efficiently
    
    #### 📊 Technology Stack
    
    - **Backend**: FastAPI, PyTorch, PyTorch Geometric, NetworkX
    - **Frontend**: Streamlit
    - **ML Models**: HTGAT (Heterogeneous Temporal Graph Attention Networks)
    - **Features**: Behavioral Biometrics, Velocity Analysis, Entropy Calculation
    
    #### 🔍 Detection Capabilities
    
    1. **Mule Account Chains**: Detects layered money laundering patterns
    2. **Star Patterns**: Identifies central distribution hubs
    3. **Mesh Networks**: Uncovers complex interconnected fraud rings
    4. **Behavioral Anomalies**: Analyzes keystroke dynamics and user behavior
    5. **Velocity Patterns**: Detects rapid transaction sequences
    
    #### 🎓 System Modes
    
    - **DEMO MODE**: Uses simulated risk scoring for testing (active when PyTorch Geometric is not fully installed)
    - **PRODUCTION MODE**: Full neural network-based fraud detection with trained models
    
    #### 📞 API Endpoints
    
    - `GET /health`: System health check
    - `GET /stats`: System statistics
    - `POST /api/v1/fraud/check`: Single transaction check
    - `POST /api/v1/fraud/batch`: Batch transaction processing
    
    #### 🚀 Getting Started
    
    1. **Start API Server**: `python -m uvicorn src.api.main:app --reload`
    2. **Launch Web App**: `streamlit run app.py`
    3. **Test Transactions**: Use the Single Transaction Check page
    4. **Batch Process**: Upload CSV files for bulk analysis
    
    #### 📚 Documentation
    
    - Interactive API Docs: http://localhost:8000/docs
    - Project README: See README.md
    - Deployment Guide: See DEPLOYMENT.md
    
    #### 🏆 Built for Excellence
    
    This system is designed to meet and exceed the requirements of the 2026 National Fraud Prevention Challenge,
    providing state-of-the-art fraud detection with explainability and real-time performance.
    
    ---
    
    **Version**: 2.0.0  
    **Status**: Production Ready  
    **Last Updated**: February 26, 2026
    
    """)
    
    st.info("💡 **Tip**: Navigate through different pages using the sidebar to explore all features!")

# Footer
st.markdown("---")
st.markdown(
    '<p style="text-align: center; color: #666;">© 2026 AegisGraph Sentinel 2.0 | Detecting the Flow, Protecting the Soul 🛡️</p>',
    unsafe_allow_html=True
)
