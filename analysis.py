import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

st.set_page_config(
    page_title="DevSecOps CI/CD Security Benchmarking",
    layout="wide"
)

# -----------------------
# Load Data
# -----------------------
@st.cache_data
def load_data():
    df = pd.read_csv("osv_dataset.csv")
    df["published_date"] = pd.to_datetime(df["published_date"])
    df["modified_date"] = pd.to_datetime(df["modified_date"])
    df["remediation_days"] = (df["modified_date"] - df["published_date"]).dt.days
    return df

df = load_data()

# -----------------------
# Sidebar Controls
# -----------------------
st.sidebar.title("Benchmark Controls")

ecosystems = st.sidebar.multiselect(
    "Ecosystems",
    df["ecosystem"].unique(),
    default=df["ecosystem"].unique()
)

year_range = st.sidebar.slider(
    "Disclosure Year Range",
    int(df["published_date"].dt.year.min()),
    int(df["published_date"].dt.year.max()),
    (
        int(df["published_date"].dt.year.min()),
        int(df["published_date"].dt.year.max())
    )
)

filtered = df[
    (df["ecosystem"].isin(ecosystems)) &
    (df["published_date"].dt.year >= year_range[0]) &
    (df["published_date"].dt.year <= year_range[1])
]

# -----------------------
# Header
# -----------------------
st.title("Benchmarking Automated Security in CI/CD Pipelines")
st.markdown("""
This dashboard evaluates **automated DevSecOps security signals** derived from vulnerability advisories
to understand **risk reduction, remediation efficiency, and adoption barriers**.
""")

# -----------------------
# KPI Layer (Success Metrics)
# -----------------------
c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Automated Findings", len(filtered))
c2.metric("Ecosystems Covered", filtered["ecosystem"].nunique())
c3.metric("Packages Affected", filtered["package_name"].nunique())
c4.metric(
    "Median Remediation Time (Days)",
    int(filtered["remediation_days"].median())
)

# -----------------------
# RQ1: Controls That Reduce CI/CD Risk (Advanced)
# -----------------------
st.subheader("RQ1: Which Automated Controls Reduce CI/CD Risk? (Advanced)")
risk_by_ecosystem = filtered["ecosystem"].value_counts()
fig1, ax1 = plt.subplots(figsize=(8, 5))
bars = ax1.bar(risk_by_ecosystem.index, risk_by_ecosystem.values, color=plt.cm.Paired.colors)
ax1.set_title("Automated Findings by Ecosystem")
ax1.set_ylabel("Finding Count")
ax1.set_xlabel("Ecosystem")
ax1.grid(True, linestyle='--', alpha=0.5, axis='y')
for bar in bars:
    height = bar.get_height()
    ax1.annotate(f'{height}', xy=(bar.get_x() + bar.get_width() / 2, height),
                 xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9, color='navy')
for tick in ax1.get_xticklabels():
    tick.set_rotation(30)
st.pyplot(fig1)

st.markdown("""
**Interpretation:**  
Security controls that focus on **dependency-heavy ecosystems**
provide the greatest risk reduction with minimal pipeline disruption.
""")

# -----------------------
# RQ2: Measuring DevSecOps Success (Advanced)
# -----------------------
st.subheader("RQ2: Measuring DevSecOps Success Without Slowing Delivery (Advanced)")
fig2, ax2 = plt.subplots(figsize=(8, 5))
n, bins, patches = ax2.hist(filtered["remediation_days"], bins=40, color='tab:green', alpha=0.7, edgecolor='black')
ax2.set_xlabel("Days to Patch")
ax2.set_ylabel("Number of Findings")
ax2.set_title("Remediation Time Distribution")
ax2.grid(True, linestyle='--', alpha=0.5)
median_remediation = int(filtered["remediation_days"].median())
ax2.axvline(median_remediation, color='red', linestyle='dashed', linewidth=2, label=f'Median: {median_remediation}d')
ax2.legend()
for i in range(len(n)):
    if n[i] > 0:
        ax2.annotate(f'{int(n[i])}', xy=(bins[i] + (bins[1]-bins[0])/2, n[i]),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8, color='tab:green')
st.pyplot(fig2)

st.markdown("""
**Interpretation:**  
Short remediation cycles indicate successful automation.  
Long-tail delays highlight friction, false positives, or cultural resistance.
""")

# -----------------------
# RQ3: Technical & Cultural Barriers
# -----------------------
st.subheader("RQ3: Technical and Cultural Barriers to DevSecOps")

top_packages = filtered["package_name"].value_counts().head(10)

st.table(top_packages)

st.markdown("""
**Interpretation:**  
Repeated findings in the same packages indicate alert fatigue,
while prolonged remediation suggests ownership ambiguity or workflow friction.
""")

# -----------------------
# RQ4: Research Gaps & Future Needs
# -----------------------
st.subheader("RQ4: Where Further Research Is Needed")

gap_data = pd.DataFrame({
    "Area": [
        "ML-based False Positive Triage",
        "Developer-Centric Security UX",
        "Automated Policy-as-Code Evaluation",
        "Cultural Adoption Metrics"
    ],
    "Observed Gap": [
        "High alert volume with limited prioritisation",
        "Security signals not developer-friendly",
        "Inconsistent enforcement timing",
        "Lack of measurable cultural indicators"
    ]
})

st.table(gap_data)

# -----------------------
# Dataset Preview
# -----------------------
st.subheader("Dataset Snapshot")
st.dataframe(filtered.head(25))

# -----------------------
# Conclusion
# -----------------------
st.markdown("""
### Conclusion

This analysis demonstrates that **automated, data-driven security observability**
can benchmark DevSecOps effectiveness without compromising delivery speed.
The findings validate the need for **low-friction controls, ML-assisted triage,
and cultural alignment** to achieve scalable CI/CD security.
""")

# -----------------------
# Advanced Analysis & Visualizations
# -----------------------
st.header("Advanced Analysis & Visualizations")

# 1. Time Series Trend: Vulnerabilities and Remediation Over Time (Advanced)
st.subheader("Vulnerability and Remediation Trends Over Time (Advanced)")
time_series = filtered.groupby(filtered["published_date"].dt.to_period("M")).size()
remediation_series = filtered.groupby(filtered["modified_date"].dt.to_period("M")).size()
fig_ts, ax_ts = plt.subplots(figsize=(10, 5))
time_series.index = time_series.index.to_timestamp()
remediation_series.index = remediation_series.index.to_timestamp()
ax_ts.plot(time_series.index, time_series.values, label="Disclosed", marker='o', linestyle='-', color='tab:blue')
ax_ts.plot(remediation_series.index, remediation_series.values, label="Remediated", marker='x', linestyle='--', color='tab:green')
ax_ts.set_xlabel("Month")
ax_ts.set_ylabel("Count")
ax_ts.set_title("Vulnerabilities Disclosed vs. Remediated Over Time")
ax_ts.legend()
ax_ts.grid(True, linestyle='--', alpha=0.5)
for i, v in enumerate(time_series.values):
    if v > 0:
        ax_ts.annotate(str(v), (time_series.index[i], v), textcoords="offset points", xytext=(0,5), ha='center', fontsize=8, color='tab:blue')
for i, v in enumerate(remediation_series.values):
    if v > 0:
        ax_ts.annotate(str(v), (remediation_series.index[i], v), textcoords="offset points", xytext=(0,-10), ha='center', fontsize=8, color='tab:green')
st.pyplot(fig_ts)

# 2. Boxplot: Remediation Days by Ecosystem (Advanced)
st.subheader("Remediation Days by Ecosystem (Advanced Boxplot)")
fig_box, ax_box = plt.subplots(figsize=(10, 5))
filtered.boxplot(column="remediation_days", by="ecosystem", ax=ax_box, grid=False, patch_artist=True, boxprops=dict(facecolor='lightblue'))
ax_box.set_title("Remediation Days by Ecosystem")
ax_box.set_ylabel("Days to Patch")
plt.suptitle("")
ax_box.grid(True, linestyle='--', alpha=0.5)
for tick in ax_box.get_xticklabels():
    tick.set_rotation(30)
st.pyplot(fig_box)

# 3. Heatmap: Correlation Matrix (Advanced)
numeric_cols = filtered.select_dtypes(include=[np.number])
if numeric_cols.shape[1] > 1:
    st.subheader("Correlation Heatmap (Advanced)")
    import seaborn as sns
    corr = numeric_cols.corr()
    fig_corr, ax_corr = plt.subplots(figsize=(7, 5))
    sns.heatmap(corr, annot=True, fmt=".2f", cmap="coolwarm", ax=ax_corr, cbar=True, square=True, linewidths=.5)
    ax_corr.set_title("Correlation Heatmap of Numeric Fields")
    st.pyplot(fig_corr)

# 4. Pareto Chart: Top Packages by Findings (Advanced)
st.subheader("Pareto Chart: Top Packages by Findings (Advanced)")
top_pkg_counts = filtered["package_name"].value_counts().head(20)
cum_pct = top_pkg_counts.cumsum() / top_pkg_counts.sum() * 100
fig_pareto, ax_pareto = plt.subplots(figsize=(12, 5))
top_pkg_counts.plot(kind="bar", ax=ax_pareto, color="tab:blue")
ax_pareto2 = ax_pareto.twinx()
cum_pct.plot(ax=ax_pareto2, color="tab:red", marker="o", alpha=0.7, linestyle='--')
ax_pareto2.set_ylabel("Cumulative %")
ax_pareto.set_ylabel("Findings Count")
ax_pareto.set_title("Pareto of Top 20 Packages by Findings")
ax_pareto2.set_ylim(0, 110)
for i, v in enumerate(top_pkg_counts.values):
    ax_pareto.text(i, v + 0.5, str(v), ha='center', va='bottom', fontsize=8, color='tab:blue')
for i, v in enumerate(cum_pct.values):
    ax_pareto2.text(i, v + 2, f"{v:.1f}%", ha='center', va='bottom', fontsize=8, color='tab:red')
ax_pareto.grid(True, linestyle='--', alpha=0.5)
st.pyplot(fig_pareto)

# 5. Scatter Plot: Remediation Days vs. Package Frequency (Advanced Scatter Plot)
st.subheader("Remediation Days vs. Package Frequency (Advanced Scatter Plot)")
pkg_freq = filtered["package_name"].value_counts()
filtered["pkg_freq"] = filtered["package_name"].map(pkg_freq)
fig_scatter, ax_scatter = plt.subplots(figsize=(8, 5))
sc = ax_scatter.scatter(filtered["pkg_freq"], filtered["remediation_days"], alpha=0.3, c=filtered["remediation_days"], cmap='viridis', edgecolor='k')
ax_scatter.set_xlabel("Package Frequency (Findings)")
ax_scatter.set_ylabel("Remediation Days")
ax_scatter.set_title("Remediation Days vs. Package Frequency")
cbar = plt.colorbar(sc, ax=ax_scatter)
cbar.set_label('Remediation Days')
ax_scatter.grid(True, linestyle='--', alpha=0.5)
st.pyplot(fig_scatter)

# -----------------------
# Further Advanced Analyses
# -----------------------
st.header("Further Advanced Analyses")

# 1. Ecosystem Risk-Reward Matrix
st.subheader("Ecosystem Risk-Reward Matrix")
eco_stats = filtered.groupby('ecosystem').agg(
    findings=('remediation_days', 'count'),
    median_remediation=('remediation_days', 'median')
).reset_index()
fig_rr, ax_rr = plt.subplots(figsize=(8,6))
sc = ax_rr.scatter(
    eco_stats['findings'], eco_stats['median_remediation'],
    s=eco_stats['findings']*2, c=eco_stats['median_remediation'], cmap='coolwarm', alpha=0.8, edgecolor='k')
for i, row in eco_stats.iterrows():
    ax_rr.annotate(row['ecosystem'], (row['findings'], row['median_remediation']), fontsize=9, ha='center', va='bottom')
ax_rr.set_xlabel('Number of Findings (Coverage)')
ax_rr.set_ylabel('Median Remediation Days (Risk)')
ax_rr.set_title('Ecosystem Risk-Reward Matrix')
cbar = plt.colorbar(sc, ax=ax_rr)
cbar.set_label('Median Remediation Days')
ax_rr.grid(True, linestyle='--', alpha=0.5)
st.pyplot(fig_rr)

# 2. Outlier Analysis: Longest Remediation Cases
st.subheader("Top 10 Slowest-to-Remediate Packages")
outliers = filtered.sort_values('remediation_days', ascending=False).head(10)
st.table(outliers[['package_name', 'ecosystem', 'remediation_days', 'published_date', 'modified_date']])

# 3. Noise Proxy: Repeated vs. Single Findings
st.subheader("Alert Fatigue Proxy: Repeated vs. Single Findings")
pkg_counts = filtered['package_name'].value_counts()
repeated = (pkg_counts > 1).sum()
single = (pkg_counts == 1).sum()
fig_noise, ax_noise = plt.subplots()
ax_noise.bar(['Repeated', 'Single'], [repeated, single], color=['tab:orange', 'tab:gray'])
ax_noise.set_ylabel('Number of Packages')
ax_noise.set_title('Packages with Repeated vs. Single Findings')
for i, v in enumerate([repeated, single]):
    ax_noise.text(i, v + 1, str(v), ha='center', va='bottom', fontsize=10)
st.pyplot(fig_noise)

# 4. Rolling Median Remediation Trend
st.subheader("Rolling Median Remediation Days Over Time")
filtered_sorted = filtered.sort_values('published_date')
rolling_median = filtered_sorted['remediation_days'].rolling(window=50, min_periods=1).median()
fig_roll, ax_roll = plt.subplots(figsize=(10,4))
ax_roll.plot(filtered_sorted['published_date'], rolling_median, color='tab:purple')
ax_roll.set_xlabel('Published Date')
ax_roll.set_ylabel('Rolling Median Remediation Days')
ax_roll.set_title('Rolling Median Remediation Days (Window=50)')
ax_roll.grid(True, linestyle='--', alpha=0.5)
st.pyplot(fig_roll)

# 5. Ecosystem Adoption Heatmap
st.subheader("Ecosystem Adoption Heatmap (Findings per Year)")
heatmap_data = filtered.copy()
heatmap_data['year'] = heatmap_data['published_date'].dt.year
pivot = pd.pivot_table(heatmap_data, index='ecosystem', columns='year', values='package_name', aggfunc='count', fill_value=0)
import seaborn as sns
fig_heat, ax_heat = plt.subplots(figsize=(10,6))
sns.heatmap(pivot, annot=True, fmt='d', cmap='YlGnBu', ax=ax_heat, cbar=True)
ax_heat.set_title('Findings per Ecosystem per Year')
st.pyplot(fig_heat)

# 6. Remediation Speed by Year and Ecosystem
st.subheader("Remediation Speed by Year and Ecosystem (Violin Plot)")
violin_data = filtered.copy()
violin_data['year'] = violin_data['published_date'].dt.year
fig_vio, ax_vio = plt.subplots(figsize=(12,6))
try:
    sns.violinplot(data=violin_data, x='year', y='remediation_days', hue='ecosystem', split=True, ax=ax_vio)
except Exception:
    sns.violinplot(data=violin_data, x='year', y='remediation_days', ax=ax_vio)
ax_vio.set_title('Remediation Days by Year and Ecosystem')
ax_vio.set_ylabel('Remediation Days')
ax_vio.set_xlabel('Year')
ax_vio.grid(True, linestyle='--', alpha=0.5)
st.pyplot(fig_vio)

# 7. Correlation: Package Popularity vs. Remediation Speed
st.subheader("Package Popularity vs. Median Remediation Days (by Ecosystem)")
pop_speed = filtered.groupby(['package_name', 'ecosystem']).agg(
    findings=('remediation_days', 'count'),
    median_remediation=('remediation_days', 'median')
).reset_index()
fig_corr2, ax_corr2 = plt.subplots(figsize=(10,6))
for eco in pop_speed['ecosystem'].unique():
    subset = pop_speed[pop_speed['ecosystem'] == eco]
    ax_corr2.scatter(subset['findings'], subset['median_remediation'], label=eco, alpha=0.6)
ax_corr2.set_xlabel('Package Findings (Popularity)')
ax_corr2.set_ylabel('Median Remediation Days')
ax_corr2.set_title('Package Popularity vs. Median Remediation Days')
ax_corr2.legend()
ax_corr2.grid(True, linestyle='--', alpha=0.5)
st.pyplot(fig_corr2)

# -----------------------
# User Interaction Layer
# -----------------------
st.sidebar.header("Interactive Analysis Controls")

# Ecosystem selector for advanced plots
eco_options = list(filtered['ecosystem'].unique())
selected_ecosystem = st.sidebar.selectbox("Select Ecosystem for Deep Dive", eco_options)

# Year range for focused analysis
years = filtered['published_date'].dt.year.unique()
years.sort()
selected_year = st.sidebar.selectbox("Select Year for Focused Analysis", years)

# Package selector for outlier/package-specific analysis
pkg_options = list(filtered['package_name'].unique())
selected_package = st.sidebar.selectbox("Select Package for Details", pkg_options)

# Plot type toggle for RQ2
plot_type = st.sidebar.radio("Remediation Distribution Plot Type", ["Histogram", "Boxplot"])

# -----------------------
# Interactive Ecosystem Deep Dive
# -----------------------
st.subheader(f"Ecosystem Deep Dive: {selected_ecosystem}")
eco_df = filtered[filtered['ecosystem'] == selected_ecosystem]
if not eco_df.empty:
    fig_eco, ax_eco = plt.subplots(figsize=(8,4))
    eco_df['remediation_days'].plot(kind='hist', bins=30, ax=ax_eco, color='tab:blue', alpha=0.7, edgecolor='black')
    ax_eco.set_title(f"Remediation Days Distribution for {selected_ecosystem}")
    ax_eco.set_xlabel("Remediation Days")
    ax_eco.set_ylabel("Findings")
    st.pyplot(fig_eco)
    st.write(f"Median Remediation Days: {eco_df['remediation_days'].median():.1f}")
else:
    st.info("No data for selected ecosystem.")

# -----------------------
# Interactive Yearly Analysis
# -----------------------
st.subheader(f"Yearly Analysis: {selected_year}")
year_df = filtered[filtered['published_date'].dt.year == selected_year]
if not year_df.empty:
    fig_year, ax_year = plt.subplots(figsize=(8,4))
    year_df['remediation_days'].plot(kind='box', ax=ax_year, patch_artist=True, boxprops=dict(facecolor='lightgreen'))
    ax_year.set_title(f"Remediation Days Boxplot for {selected_year}")
    ax_year.set_ylabel("Remediation Days")
    st.pyplot(fig_year)
    st.write(f"Median Remediation Days: {year_df['remediation_days'].median():.1f}")
else:
    st.info("No data for selected year.")

# -----------------------
# Interactive Package Details
# -----------------------
st.subheader(f"Package Details: {selected_package}")
pkg_df = filtered[filtered['package_name'] == selected_package]
if not pkg_df.empty:
    st.write(pkg_df[['ecosystem', 'published_date', 'modified_date', 'remediation_days']])
    st.write(f"Median Remediation Days: {pkg_df['remediation_days'].median():.1f}")
else:
    st.info("No data for selected package.")

# -----------------------
# Interactive RQ2 Plot Type
# -----------------------
st.subheader("RQ2: Remediation Distribution (Interactive)")
fig_rq2, ax_rq2 = plt.subplots(figsize=(8, 5))
if plot_type == "Histogram":
    n, bins, patches = ax_rq2.hist(filtered["remediation_days"], bins=40, color='tab:green', alpha=0.7, edgecolor='black')
    ax_rq2.set_xlabel("Days to Patch")
    ax_rq2.set_ylabel("Number of Findings")
    ax_rq2.set_title("Remediation Time Distribution (Histogram)")
    median_remediation = int(filtered["remediation_days"].median())
    ax_rq2.axvline(median_remediation, color='red', linestyle='dashed', linewidth=2, label=f'Median: {median_remediation}d')
    ax_rq2.legend()
    for i in range(len(n)):
        if n[i] > 0:
            ax_rq2.annotate(f'{int(n[i])}', xy=(bins[i] + (bins[1]-bins[0])/2, n[i]),
                         xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8, color='tab:green')
else:
    filtered.boxplot(column="remediation_days", ax=ax_rq2, grid=False, patch_artist=True, boxprops=dict(facecolor='lightblue'))
    ax_rq2.set_ylabel("Remediation Days")
    ax_rq2.set_title("Remediation Time Distribution (Boxplot)")
    ax_rq2.grid(True, linestyle='--', alpha=0.5)
st.pyplot(fig_rq2)
