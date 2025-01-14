import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

def analyze_traceroute_results(csv_file):
    """
    Analyze the traceroute results from CSV file
    """
    # Read CSV file
    df = pd.read_csv(csv_file)
    
    # 1. Basic Statistics
    total_traces = len(df)
    ecn_changed_traces = len(df[df['ecn_changed'] == 'yes'])
    
    print("=== Basic Statistics ===")
    print(f"Total traceroutes: {total_traces}")
    print(f"ECN changes detected: {ecn_changed_traces}")
    print(f"ECN change ratio: {(ecn_changed_traces/total_traces)*100:.2f}%")
    
    # 2. Analyze hop numbers where ECN changes occurred
    if ecn_changed_traces > 0:
        hop_stats = df[df['ecn_changed'] == 'yes']['ecn_change_hop'].value_counts()
        print("\n=== ECN Change Hop Statistics ===")
        print("Number of ECN changes per hop:")
        print(hop_stats.to_string())
        
        # Average hop number where changes occur
        avg_change_hop = df[df['ecn_changed'] == 'yes']['ecn_change_hop'].mean()
        print(f"\nAverage hop number for ECN changes: {avg_change_hop:.2f}")
    
    # 3. Analyze IPs where changes frequently occur
    if ecn_changed_traces > 0:
        print("\n=== Most Common ECN Change IPs ===")
        ip_stats = df[df['ecn_changed'] == 'yes']['ecn_change_ip'].value_counts().head(10)
        print(ip_stats.to_string())
    
    # 4. Analysis by destination domain
    print("\n=== ECN Change Statistics by Domain ===")
    domain_stats = df.groupby('domain')['ecn_changed'].value_counts(normalize=True)
    domain_stats = domain_stats.unstack().fillna(0)
    print(domain_stats.to_string())
    
    # 5. Visualization: Distribution of ECN change hops
    if ecn_changed_traces > 0:
        plt.figure(figsize=(10, 6))
        df[df['ecn_changed'] == 'yes']['ecn_change_hop'].hist(bins=20)
        plt.title('Distribution of ECN Changes by Hop Number')
        plt.xlabel('Hop Number')
        plt.ylabel('Frequency')
        plt.savefig('ecn_change_hop_distribution.png')
        plt.close()

    # 6. Additional Analysis: Path length statistics
    print("\n=== Path Length Statistics ===")
    print(f"Average path length: {df['total_hops'].mean():.2f}")
    print(f"Minimum path length: {df['total_hops'].min()}")
    print(f"Maximum path length: {df['total_hops'].max()}")

    # 7. ECN change patterns by source IP
    print("\n=== ECN Change Patterns by Source IP ===")
    source_stats = df.groupby('source_ip')['ecn_changed'].value_counts(normalize=True)
    source_stats = source_stats.unstack().fillna(0)
    print(source_stats.head().to_string())

if __name__ == "__main__":
    # Specify your CSV file path
    csv_file = "analysis_results/traceroute_analysis_latest.csv"
    analyze_traceroute_results(csv_file) 