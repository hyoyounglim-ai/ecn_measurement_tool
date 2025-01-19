import paramiko
import os
from pathlib import Path
import zipfile
import stat

def prepare_ssh_key():
    # SSH 키 파일 경로 설정
    zip_path = './secret/id_rsa.zip'
    key_dir = Path('./secret')
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
    print("\nStarting file upload process...")
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
    
    print(f"\nUploading files to {len(nodes)} nodes...")
    
    # 업로드할 파일 목록 설정
    files_to_upload = [
        {'dir': Path('results'), 'pattern': '*.csv'},  # 기존 결과 파일
        {'dir': Path('.'), 'pattern': 'ecn_analysis_results_*.csv'},  # 분석 결과
        {'dir': Path('.'), 'pattern': 'sae_only_results_*.csv'}  # SAE-only 결과
    ]
    
    for node in nodes:
        print(f"\nConnecting to {node['hostname']}...")
        try:
            # SSH 연결 설정
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=node['hostname'],
                username=node['username'],
                key_filename=node['key_file']
            )
            print(f"Successfully connected to {node['hostname']}")
            
            # SFTP 설정
            sftp = ssh.open_sftp()
            print("SFTP connection established")
            
            # 원격 서버에 업로드
            remote_path = '/users/jevousai/data/'
            try:
                # 원격 디렉토리 존재 여부 확인 및 생성
                try:
                    sftp.stat(remote_path)
                except FileNotFoundError:
                    print(f"Creating remote directory: {remote_path}")
                    sftp.mkdir(remote_path)
                
                # 각 디렉토리의 파일들을 업로드
                total_uploaded = 0
                for file_config in files_to_upload:
                    local_dir = file_config['dir']
                    if not local_dir.exists():
                        print(f"Warning: Directory {local_dir} does not exist, skipping...")
                        continue
                    
                    local_files = list(local_dir.glob(file_config['pattern']))
                    print(f"Found {len(local_files)} files matching {file_config['pattern']} in {local_dir}")
                    
                    for file_path in local_files:
                        print(f"Uploading {file_path.name}...")
                        sftp.put(
                            str(file_path),
                            os.path.join(remote_path, file_path.name)
                        )
                        total_uploaded += 1
                
                print(f"Successfully uploaded {total_uploaded} files")
            except Exception as e:
                print(f"Error uploading to {node['hostname']}: {e}")
            
            sftp.close()
            ssh.close()
            print(f"Connection to {node['hostname']} closed")
        except Exception as e:
            print(f"Error connecting to {node['hostname']}: {e}")

    print("\nUpload process completed!")

if __name__ == "__main__":
    collect_results_from_nodes()