
import os

import httpx
import pandas as pd
import streamlit as st


# ============================================================
# STREAMLIT PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI Security Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# CONFIGURATION
# ============================================================

API_URL = os.getenv(
    "GATEWAY_URL",
    "http://127.0.0.1:8000",
).rstrip("/")


# ============================================================
# API HELPER
# ============================================================

def api_request(
    method: str,
    path: str,
    payload=None,
):

    admin_key = st.session_state.get(
        "admin_key", ""
    )

    headers = {
        "x-admin-key": admin_key,
    }

    try:

        with httpx.Client(
            base_url=API_URL,
            timeout=15.0,
        ) as client:

            response = client.request(
                method=method,
                url=path,
                headers=headers,
                json=payload,
            )

            response.raise_for_status()

            return response.json()

    except httpx.HTTPStatusError as exc:

        status_code = exc.response.status_code

        if status_code == 401:
            st.error(
                "Administrator authentication failed. "
                "Check your API key."
            )

        elif status_code == 503:
            st.error(
                "Administrator authentication is not "
                "configured on the FastAPI server."
            )

        else:
            st.error(
                f"API request failed: HTTP {status_code}"
            )

        return None

    except httpx.RequestError:

        st.error(
            "Cannot connect to FastAPI. "
            "Make sure the gateway is running."
        )

        return None


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🛡️ Security Gateway")

st.sidebar.caption(
    "Context-Aware Security Gateway "
    "for Autonomous AI Agents"
)

st.sidebar.divider()

st.sidebar.text_input(
    "Administrator API Key",
    type="password",
    key="admin_key",
    help=(
        "Use the ADMIN_API_KEY configured "
        "on your FastAPI server."
    ),
)

if not st.session_state.get("admin_key"):

    st.title("Administrator Authentication")

    st.info(
        "Enter your administrator API key "
        "in the sidebar to open the dashboard."
    )

    st.stop()


page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Agent Activity",
        "Resource Activity",
        "Risk Monitoring",
        "Approval Queue",
        "Audit Logs",
    ],
)

st.sidebar.divider()

if st.sidebar.button("Refresh Data"):
    st.rerun()

st.sidebar.caption(
    "Data refreshes when you navigate, "
    "refresh, or interact with the dashboard."
)


# ============================================================
# LOAD MONITORING DATA
# ============================================================

dashboard_data = api_request(
    "GET",
    "/monitoring/dashboard?limit=500",
)

if dashboard_data is None:
    st.stop()


overview = dashboard_data.get(
    "overview", {}
)

decisions = dashboard_data.get(
    "decision_distribution", {}
)

risk_distribution = dashboard_data.get(
    "risk_distribution", {}
)

agent_activity = dashboard_data.get(
    "agent_activity", []
)

resource_activity = dashboard_data.get(
    "resource_activity", []
)

recent_requests = dashboard_data.get(
    "recent_requests", []
)


# ============================================================
# 1. OVERVIEW PAGE
# ============================================================

if page == "Overview":

    st.title("Security Gateway Overview")

    st.caption(
        "Organization-wide access decisions "
        "and security monitoring"
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Requests",
        overview.get("total_requests", 0),
    )

    col2.metric(
        "Allowed Requests",
        overview.get("allowed_requests", 0),
    )

    col3.metric(
        "Blocked Requests",
        overview.get("blocked_requests", 0),
    )

    col4, col5, col6 = st.columns(3)

    col4.metric(
        "High-Risk Requests",
        overview.get("high_risk_requests", 0),
    )

    col5.metric(
        "Pending Approvals",
        overview.get("pending_approvals", 0),
    )

    col6.metric(
        "Total Agents",
        overview.get("total_agents", 0),
    )

    st.divider()

    left, right = st.columns(2)

    with left:

        st.subheader("Security Decisions")

        df = pd.DataFrame(
            [
                {
                    "Decision": name,
                    "Requests": count,
                }
                for name, count in decisions.items()
            ]
        )

        st.bar_chart(
            df.set_index("Decision")
        )

    with right:

        st.subheader("Risk Distribution")

        df = pd.DataFrame(
            [
                {
                    "Risk Level": name,
                    "Requests": count,
                }
                for name, count
                in risk_distribution.items()
            ]
        )

        st.bar_chart(
            df.set_index("Risk Level")
        )

    st.divider()

    st.subheader("Recent Access Requests")

    if recent_requests:

        st.dataframe(
            pd.DataFrame(
                recent_requests[:20]
            ),
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info("No access requests recorded yet.")


# ============================================================
# 2. AGENT ACTIVITY
# ============================================================

elif page == "Agent Activity":

    st.title("AI Agent Activity")

    st.caption(
        "Monitor simulated Sales, HR, "
        "Finance and Research agents"
    )

    if not agent_activity:

        st.info("No agents are available.")

    else:

        df = pd.DataFrame(
            agent_activity
        )

        st.subheader("Agent Summary")

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Requests by Agent")

        st.bar_chart(
            df.set_index("name")[
                ["total_requests", "blocked_requests"]
            ]
        )

        st.subheader("Agent Request History")

        options = {
            item["name"]: item["agent_code"]
            for item in agent_activity
        }

        selected_name = st.selectbox(
            "Select Agent",
            list(options.keys()),
        )

        selected_code = options[selected_name]

        records = [
            r for r in recent_requests
            if r["agent_code"] == selected_code
        ]

        if records:

            st.dataframe(
                pd.DataFrame(records),
                use_container_width=True,
                hide_index=True,
            )

        else:
            st.info(
                "No recent requests for this agent."
            )


# ============================================================
# 3. RESOURCE ACTIVITY
# ============================================================

elif page == "Resource Activity":

    st.title("Resource Activity")

    st.caption(
        "Monitor access to protected "
        "organizational resources"
    )

    if not resource_activity:

        st.info("No resources are available.")

    else:

        df = pd.DataFrame(
            resource_activity
        )

        st.subheader("Protected Resources")

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Resource Usage")

        st.bar_chart(
            df.set_index("name")[
                ["total_requests", "blocked_requests"]
            ]
        )

        sensitivity_filter = st.selectbox(
            "Sensitivity Level",
            [
                "ALL",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ],
        )

        if sensitivity_filter == "ALL":
            filtered = df

        else:
            filtered = df[
                df["sensitivity"]
                == sensitivity_filter
            ]

        st.subheader("Filtered Resources")

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# 4. RISK MONITORING
# ============================================================

elif page == "Risk Monitoring":

    st.title("Risk Monitoring")

    st.caption(
        "Review security risk scores "
        "and suspicious access requests"
    )

    df = pd.DataFrame(
        recent_requests
    )

    if df.empty:

        st.info(
            "No risk assessments available."
        )

    else:

        scored = df.dropna(
            subset=["risk_score"]
        ).copy()

        if scored.empty:

            st.info(
                "No scored requests yet."
            )

        else:

            st.subheader("Risk Score Statistics")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Average Risk",
                round(
                    scored["risk_score"].mean(),
                    2,
                ),
            )

            col2.metric(
                "Maximum Risk",
                int(
                    scored["risk_score"].max()
                ),
            )

            col3.metric(
                "Scored Recent Requests",
                len(scored),
            )

            st.subheader("Recent Risk Scores")

            chart_df = scored[
                ["request_code", "risk_score"]
            ].copy()

            st.line_chart(
                chart_df.set_index("request_code")
            )

            st.subheader("Filter by Risk Level")

            selected_level = st.selectbox(
                "Risk Level",
                [
                    "ALL",
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                ],
            )

            if selected_level != "ALL":

                scored = scored[
                    scored["risk_level"]
                    == selected_level
                ]

            st.dataframe(
                scored,
                use_container_width=True,
                hide_index=True,
            )

            st.caption(
                "Statistics above are calculated "
                "from the recent requests returned "
                "by the monitoring API."
            )


# ============================================================
# 5. HUMAN APPROVAL QUEUE
# ============================================================

elif page == "Approval Queue":

    st.title("Human Approval Queue")

    st.caption(
        "Review high-risk requests "
        "before resource execution"
    )

    approvals = api_request(
        "GET",
        "/approvals",
    )

    if approvals is None:
        st.stop()

    pending = [
        approval
        for approval in approvals
        if approval["status"] == "PENDING"
    ]

    st.metric(
        "Pending Approvals",
        len(pending),
    )

    if not pending:

        st.success(
            "No pending approval requests."
        )

    else:

        st.dataframe(
            pd.DataFrame(pending),
            use_container_width=True,
            hide_index=True,
        )

        choices = {
            (
                f"Approval #{item['approval_id']} - "
                f"{item['agent_code']} - "
                f"{item['action']}"
            ): item
            for item in pending
        }

        selected_label = st.selectbox(
            "Select Request",
            list(choices.keys()),
        )

        selected = choices[selected_label]

        st.subheader("Selected Request Details")

        st.json(selected)

        st.warning(
            "Review the request and its risk "
            "before approving execution."
        )

        comment = st.text_area(
            "Administrator Comment",
        )

        left, right = st.columns(2)

        with left:

            if st.button(
                "Approve Request",
                type="primary",
                use_container_width=True,
            ):

                result = api_request(
                    "POST",
                    (
                        "/approvals/"
                        f"{selected['approval_id']}"
                        "/approve"
                    ),
                    {"comment": comment},
                )

                if result is not None:

                    st.success(
                        "Approval processed: "
                        + result["final_outcome"]
                    )

                    st.rerun()

        with right:

            if st.button(
                "Reject Request",
                use_container_width=True,
            ):

                result = api_request(
                    "POST",
                    (
                        "/approvals/"
                        f"{selected['approval_id']}"
                        "/reject"
                    ),
                    {"comment": comment},
                )

                if result is not None:

                    st.success(
                        "Rejection processed: "
                        + result["final_outcome"]
                    )

                    st.rerun()

    st.divider()

    st.subheader("Approval History")

    if approvals:

        st.dataframe(
            pd.DataFrame(approvals),
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# 6. AUDIT LOGS
# ============================================================

elif page == "Audit Logs":

    st.title("Audit Logs")

    st.caption(
        "Inspect access decisions and "
        "recorded final outcomes"
    )

    logs = api_request(
        "GET",
        "/audit-logs",
    )

    if logs is None:
        st.stop()

    if not logs:

        st.info("No audit records found.")

    else:

        df = pd.DataFrame(logs)

        search_text = st.text_input(
            "Search Agent, Resource or Reason"
        )

        if search_text:

            mask = df.astype(str).apply(
                lambda col: col.str.contains(
                    search_text,
                    case=False,
                    regex=False,
                    na=False,
                )
            ).any(axis=1)

            df = df[mask]

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Detailed Request Inspection")

        request_id = st.number_input(
            "Request Database ID",
            min_value=1,
            step=1,
        )

        if st.button("View Request Details"):

            details = api_request(
                "GET",
                f"/requests/{int(request_id)}",
            )

            if details is not None:
                st.json(details)
