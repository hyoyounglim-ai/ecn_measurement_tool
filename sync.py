import paramiko
import os
from pathlib import Path
import zipfile
import stat

def prepare_ssh_key():
    # SSH 키 파일 경로 설정
    zip_path = 'ecn_measurement_tool/secret/id_rsa.zip'
    key_dir = Path('ecn_measurement_tool/secret')
    key_path = key_dir / 'id_rsa'

    try:
        # ZIP 파일 압축 해제
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(key_dir)
        
        # SSH 키 파일 권한 설정 (400)
        key_path.chmod(stat.S_IRUSR)  # 소유자 읽기 권한만 설정 (400)
        
        print("SSH key prepared successfully")
        return str(key_path)
    except Exception as e:
        print(f"Error preparing SSH key: {e}")
        raise

def collect_results_from_nodes():
    # SSH 키 준비
    key_file = prepare_ssh_key()
    
    # 노드 정보 업데이트
    nodes = [
        {
            'hostname': 'amd226.utah.cloudlab.us',
            'username': 'jevousai',
            'key_file': key_file
        },
    ]
    
    # 중앙 저장소 경로 설정
    central_dir = Path('collected_results')  # 현재 디렉토리 아래에 결과 저장
    central_dir.mkdir(exist_ok=True)
    
    for node in nodes:
        try:
            # SSH 연결 설정
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=node['hostname'],
                username=node['username'],
                key_filename=node['key_file']
            )
            
            # SFTP 설정
            sftp = ssh.open_sftp()
            
            # 노드별 디렉토리 생성
            node_dir = central_dir / node['hostname']
            node_dir.mkdir(exist_ok=True)
            
            # 파일 전송
            remote_path = '/path/to/analysis_results/'
            try:
                for f in sftp.listdir(remote_path):
                    if f.endswith('.csv'):
                        sftp.get(
                            os.path.join(remote_path, f),
                            str(node_dir / f)
                        )
            except Exception as e:
                print(f"Error collecting from {node['hostname']}: {e}")
            
            sftp.close()
            ssh.close()
        except Exception as e:
            print(f"Error connecting to {node['hostname']}: {e}")

if __name__ == "__main__":
    collect_results_from_nodes()