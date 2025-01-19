import os
import glob
from datetime import datetime
import socket

def get_local_ip():
    try:
        # 외부 연결을 통해 실제 IP 확인
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        print(f"Warning: Could not get local IP: {e}")
        return "unknown"
    
def analyze_traceroute_file(file_path):
    """Analyze a single traceroute file and return the results"""
    results = {
        'source_ip': '',
        'dest_ip': '',
        'domain': '',
        'ecn_changed': False,
        'ecn_change_hop': -1,
        'ecn_change_ip': '',
        'previous_hop_ip': '',
        'total_hops': 0
    }

    # Extract source IP, destination info from filename
    # 128.110.219.137 3
    # D 4
    # 3611 5
    # correcao.pt 6
    # 51.222.41.187 7
    # 2025-01-08 8
    # 1736352766.txt 9
    filename = os.path.basename(file_path)
    if filename.startswith('Traceroute_Only_S_'):
        parts = filename.split('_')
        results['source_ip'] = parts[3]
        results['domain'] = parts[6]
        results['dest_ip'] = parts[7]
        results['date'] = parts[8]
    
    # Analyze the traceroute data
    with open(file_path, 'r') as f:
        lines = f.readlines()
        
    valid_hops = [line for line in lines if not (line.startswith('error') or line.startswith('no answer'))]
    results['total_hops'] = len(valid_hops)
    
    previous_ip = None
    for line in valid_hops:
        try:
            # Parse line: ip hop ttl sent_tos icmp_tos icmp_ecn iperror_tos iperror_ecn
            parts = line.strip().split('\t')
            if len(parts) >= 8:
                current_ip = parts[0]
                hop_num = int(parts[1])
                sent_tos = int(parts[3])
                iperror_ecn = int(parts[7])
                
                # Check if ECN was changed (sent_tos != iperror_ecn)
                if (sent_tos & 0x3) != iperror_ecn and not results['ecn_changed']:
                    results['ecn_changed'] = True
                    results['ecn_change_hop'] = hop_num
                    results['ecn_change_ip'] = current_ip
                    results['previous_hop_ip'] = previous_ip if previous_ip else 'N/A'
                
                previous_ip = current_ip
        except:
            continue
            
    return results

def analyze_all_traceroutes():
    """Analyze all traceroute files in the traceroute directory"""
    traceroute_files = glob.glob('traceroute/Traceroute_Only_*.txt')
    
    print(f"Analyzing {len(traceroute_files)} files...")
    
    # Create results directory if it doesn't exist
    if not os.path.exists('analysis_results'):
        os.makedirs('analysis_results')
    # 로컬 IP 가져오기
    local_ip = get_local_ip()
    print(f"Local IP: {local_ip}")
    

    # Prepare output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f'analysis_results/traceroute_analysis_{timestamp}_{local_ip}.csv'
    
    # Write CSV header
    with open(output_file, 'w', encoding='utf-8') as f:
        # Write CSV header
        f.write('source_ip,dest_ip,domain,date,ecn_changed,ecn_change_hop,ecn_change_ip,previous_hop_ip,total_hops,filename\n')
        
        for file_path in traceroute_files:
            results = analyze_traceroute_file(file_path)
            
            # Format as CSV row
            csv_row = [
                results['source_ip'],
                results['dest_ip'],
                results['domain'],
                results['date'],
                'True' if results['ecn_changed'] else 'False',
                str(results['ecn_change_hop']) if results['ecn_changed'] else 'N/A',
                results['ecn_change_ip'] if results['ecn_changed'] else 'N/A',
                results['previous_hop_ip'] if results['ecn_changed'] else 'N/A',
                str(results['total_hops']),
                os.path.basename(file_path),
            ]
            
            # Write CSV row
            f.write(','.join(csv_row) + '\n')
    
    print(f"\nAnalysis results have been saved to: {output_file}")

if __name__ == "__main__":
    analyze_all_traceroutes() 
    