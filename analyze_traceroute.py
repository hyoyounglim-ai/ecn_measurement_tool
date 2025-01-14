import os
import glob
from datetime import datetime

def analyze_traceroute_file(file_path):
    """Analyze a single traceroute file and return the results"""
    results = {
        'source_ip': '',
        'dest_ip': '',
        'domain': '',
        'ecn_changed': False,
        'ecn_change_hop': -1,
        'total_hops': 0
    }
    
    # Extract source IP, destination info from filename
    filename = os.path.basename(file_path)
    if filename.startswith('Traceroute_Only_S_'):
        parts = filename.split('_')
        results['source_ip'] = parts[3]
        results['domain'] = parts[5]
        results['dest_ip'] = parts[6].split('.txt')[0]
    
    # Analyze the traceroute data
    with open(file_path, 'r') as f:
        lines = f.readlines()
        
    valid_hops = [line for line in lines if not (line.startswith('error') or line.startswith('no answer'))]
    results['total_hops'] = len(valid_hops)
    
    for line in valid_hops:
        try:
            # Parse line: ip hop ttl sent_tos icmp_tos icmp_ecn iperror_tos iperror_ecn
            parts = line.strip().split('\t')
            if len(parts) >= 8:
                sent_tos = int(parts[3])
                iperror_ecn = int(parts[7])
                hop_num = int(parts[1])
                
                # Check if ECN was changed (sent_tos != iperror_ecn)
                if (sent_tos & 0x3) != iperror_ecn and not results['ecn_changed']:
                    results['ecn_changed'] = True
                    results['ecn_change_hop'] = hop_num
        except:
            continue
            
    return results

def analyze_all_traceroutes():
    """Analyze all traceroute files in the traceroute directory"""
    traceroute_files = glob.glob('traceroute/Traceroute_Only_*.txt')
    
    print("=== Traceroute Analysis Report ===")
    print(f"Analyzing {len(traceroute_files)} files\n")
    
    # Create results directory if it doesn't exist
    if not os.path.exists('analysis_results'):
        os.makedirs('analysis_results')
    
    # Prepare output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f'analysis_results/traceroute_analysis_{timestamp}.txt'
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for file_path in traceroute_files:
            results = analyze_traceroute_file(file_path)
            
            # Format the analysis results
            analysis = f"""
File: {os.path.basename(file_path)}
출발지 IP: {results['source_ip']}
목적지 IP: {results['dest_ip']}
도메인: {results['domain']}
ECN 변경 여부: {'예' if results['ecn_changed'] else '아니오'}
"""
            if results['ecn_changed']:
                analysis += f"ECN 변경된 홉: {results['ecn_change_hop']}\n"
            analysis += f"총 홉 수: {results['total_hops']}\n"
            analysis += "="*50
            
            # Write to file and print to console
            f.write(analysis)
            print(analysis)
    
    print(f"\nAnalysis results have been saved to: {output_file}")

if __name__ == "__main__":
    analyze_all_traceroutes() 