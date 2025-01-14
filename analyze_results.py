import pandas as pd
import os
import glob
from pathlib import Path
import numpy as np

def combine_and_analyze_results():
    """
    Combine all CSV files in the analysis_results directory and analyze them together
    """
    # Get all CSV files
    csv_pattern = os.path.join('analysis_results', 'traceroute_analysis_*.csv')
    csv_files = glob.glob(csv_pattern)
    
    if not csv_files:
        raise FileNotFoundError("No traceroute analysis CSV files found")
    
    print(f"Found {len(csv_files)} analysis files")
    
    # Combine all CSV files
    all_data = []
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        df['source_file'] = os.path.basename(csv_file)  # Keep track of source file
        all_data.append(df)
    
    # Concatenate all dataframes
    combined_df = pd.concat(all_data, ignore_index=True)
    
    print("\n=== Combined Analysis Results ===")
    print(f"Total number of files analyzed: {len(csv_files)}")
    print(f"Total number of traceroutes: {len(combined_df)}")
    
    # Perform analysis on combined data
    analyze_combined_data(combined_df)

def analyze_combined_data(df):
    """
    Analyze the combined dataset
    """
    # 1. Basic Statistics
    total_traces = len(df)
    ecn_changed_traces = len(df[df['ecn_changed'] == 'yes'])
    
    print("\n=== Overall Statistics ===")
    print(f"Total traceroutes: {total_traces}")
    print(f"ECN changes detected: {ecn_changed_traces}")
    print(f"Overall ECN change ratio: {(ecn_changed_traces/total_traces)*100:.2f}%")
    
    # 2. Unique Statistics
    print("\n=== Unique Entry Counts ===")
    print(f"Unique source IPs: {df['source_ip'].nunique()}")
    print(f"Unique destination IPs: {df['dest_ip'].nunique()}")
    print(f"Unique domains: {df['domain'].nunique()}")
    
    if ecn_changed_traces > 0:
        # 3. ECN Change Analysis
        print("\n=== ECN Change Statistics ===")
        
        # Hop number analysis
        hop_stats = df[df['ecn_changed'] == 'yes']['ecn_change_hop'].value_counts().sort_index()
        print("\nECN changes by hop number:")
        for hop, count in hop_stats.items():
            print(f"Hop {hop}: {count} changes ({(count/ecn_changed_traces)*100:.1f}%)")
        
        # IP analysis
        print("\nTop 10 IPs where ECN changes occur:")
        ip_stats = df[df['ecn_changed'] == 'yes']['ecn_change_ip'].value_counts()
        for ip, count in ip_stats.head(10).items():
            print(f"{ip}: {count} changes ({(count/ecn_changed_traces)*100:.1f}%)")
    
    # 4. Domain Analysis
    print("\n=== Domain Statistics ===")
    domain_stats = df.groupby('domain').agg({
        'ecn_changed': lambda x: (x == 'yes').mean(),
        'total_hops': 'mean',
        'source_file': 'count'
    }).round(2)
    
    domain_stats = domain_stats.sort_values('source_file', ascending=False)
    print("\nTop 10 domains by number of traces:")
    for domain, row in domain_stats.head(10).iterrows():
        print(f"\nDomain: {domain}")
        print(f"  Number of traces: {int(row['source_file'])}")
        print(f"  ECN change rate: {row['ecn_changed']*100:.1f}%")
        print(f"  Average hops: {row['total_hops']:.1f}")
    
    # 5. Path Length Analysis
    print("\n=== Path Length Statistics ===")
    print(f"Average path length: {df['total_hops'].mean():.2f}")
    print(f"Minimum path length: {df['total_hops'].min()}")
    print(f"Maximum path length: {df['total_hops'].max()}")
    print(f"Standard deviation: {df['total_hops'].std():.2f}")
    
    # 6. Source-Destination Pair Analysis
    print("\n=== Source-Destination Pair Analysis ===")
    pair_stats = df.groupby(['source_ip', 'dest_ip']).agg({
        'ecn_changed': lambda x: (x == 'yes').mean(),
        'source_file': 'count'
    }).round(2)
    
    print("\nTop 10 source-destination pairs by number of traces:")
    pair_stats = pair_stats.sort_values('source_file', ascending=False)
    for (src, dst), row in pair_stats.head(10).iterrows():
        print(f"\n{src} -> {dst}")
        print(f"  Number of traces: {int(row['source_file'])}")
        print(f"  ECN change rate: {row['ecn_changed']*100:.1f}%")

if __name__ == "__main__":
    try:
        combine_and_analyze_results()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        exit(1) 