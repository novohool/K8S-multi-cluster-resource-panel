from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Dict, Optional
from kubernetes import client, config, dynamic, stream
from kubernetes.client import ApiClient
import os
from typing import Dict, List
import glob
import base64
import jwt
from datetime import datetime, timedelta
import OpenSSL.crypto
import time
import tempfile
import yaml
from jose import JWTError

app = FastAPI(title="K8s Resource Viewer")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # 前端开发服务器地址
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Configuration
SECRET_KEY = "your-secret-key"  # Change this to a secure secret key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Authentication models
class Token(BaseModel):
    access_token: str
    token_type: str
    permissions: dict
    available_clusters: List[str]

class UserCredentials(BaseModel):
    username: str
    password: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Authentication functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    """验证并解析 JWT token"""
    try:
        print(f"\n[AUTH] ========== Validating token ==========")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            print(f"[AUTH] Error: Token missing username")
            raise HTTPException(
                status_code=401,
                detail={"message": "无效的认证凭据"}
            )
        print(f"[AUTH] Successfully validated token for user: {username}")
        return {"sub": username}
    except JWTError as e:
        print(f"[AUTH] JWT validation error: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail={"message": "无效的认证凭据"}
        )
    except Exception as e:
        print(f"[AUTH] Unexpected error during token validation: {str(e)}")
        raise HTTPException(
            status_code=401,
            detail={"message": f"认证失败: {str(e)}"}
        )
    finally:
        print(f"[AUTH] ========== End token validation ==========\n")

def check_user_cluster_access(username: str, password: str) -> Dict[str, Dict]:
    """
    检查用户在每个集群中的访问权限
    返回格式: {
        "cluster-name": {
            "authenticated": bool,
            "permissions": dict,
            "error": str,
            "error_details": str
        }
    }
    """
    cluster_access = {}
    
    # 获取当前文件的绝对路径
    current_file = os.path.abspath(__file__)
    # 获取项目根目录
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    # 构建kubeconfig目录的路径
    kubeconfig_dir = os.path.join(project_root, "kubeconfig")
    # 构建用户kubeconfig目录的路径
    user_kubeconfig_base_dir = os.path.join(project_root, "user_kubeconfig")
    user_kubeconfig_dir = os.path.join(user_kubeconfig_base_dir, username)
    
    print(f"[CLUSTER] ========== Starting cluster access check for user: {username} ==========")
    print(f"[CLUSTER] Project root: {project_root}")
    print(f"[CLUSTER] Main kubeconfig directory: {kubeconfig_dir}")
    print(f"[CLUSTER] User kubeconfig base directory: {user_kubeconfig_base_dir}")
    print(f"[CLUSTER] User specific kubeconfig directory: {user_kubeconfig_dir}")
    
    # 确保用户kubeconfig目录存在
    try:
        if not os.path.exists(user_kubeconfig_base_dir):
            print(f"[CLUSTER] Creating user kubeconfig base directory: {user_kubeconfig_base_dir}")
            os.makedirs(user_kubeconfig_base_dir, exist_ok=True)
        
        if not os.path.exists(user_kubeconfig_dir):
            print(f"[CLUSTER] Creating user specific kubeconfig directory: {user_kubeconfig_dir}")
            os.makedirs(user_kubeconfig_dir, exist_ok=True)
    except Exception as e:
        print(f"[CLUSTER] Error creating user kubeconfig directories: {e}")
        return cluster_access
    
    if not os.path.exists(kubeconfig_dir):
        print(f"[CLUSTER] Main kubeconfig directory does not exist: {kubeconfig_dir}")
        return cluster_access
    
    # 获取所有kubeconfig文件
    kubeconfig_files = glob.glob(os.path.join(kubeconfig_dir, "*"))
    print(f"[CLUSTER] Found {len(kubeconfig_files)} kubeconfig files")
    print(f"[CLUSTER] Kubeconfig files: {kubeconfig_files}")
    
    if not kubeconfig_files:
        print(f"[CLUSTER] No kubeconfig files found in directory: {kubeconfig_dir}")
        return cluster_access
    
    for kubeconfig in kubeconfig_files:
        cluster_name = os.path.basename(kubeconfig)
        print(f"\n[CLUSTER] ========== Processing cluster: {cluster_name} ==========")
        print(f"[CLUSTER] Using kubeconfig file: {kubeconfig}")
        
        # 构建用户特定的kubeconfig文件路径
        user_kubeconfig_file = os.path.join(user_kubeconfig_dir, f"{cluster_name}.yaml")
        print(f"[CLUSTER] User kubeconfig file path: {user_kubeconfig_file}")
        
        try:
            # 加载集群配置
            print(f"[CLUSTER] Loading cluster configuration from: {kubeconfig}")
            config.load_kube_config(kubeconfig)
            v1 = client.CoreV1Api()
            print(f"[CLUSTER] Successfully loaded cluster configuration")
            
            # 首先检查用户的secret是否存在
            try:
                # 使用label selector查找用户凭证secret
                secret_name = f"user-credentials-{username}"
                print(f"[CLUSTER] Looking for secret: {secret_name}")
                
                secrets = v1.list_namespaced_secret(
                    "default",
                    label_selector="app=k8s-resource-panel,type=user-credentials"
                )
                user_secret = None
                
                # 查找用户对应的secret
                for secret in secrets.items:
                    if secret.metadata.name == secret_name:
                        user_secret = secret
                        print(f"[CLUSTER] Found user secret: {secret_name}")
                        break
                
                if user_secret and user_secret.data:
                    # 获取secret中的密码并验证
                    stored_password = base64.b64decode(user_secret.data.get('password', '')).decode('utf-8')
                    if stored_password == password:
                        print(f"[CLUSTER] User {username} password verified for cluster {cluster_name}")
                        
                        # 检查ServiceAccount是否存在
                        try:
                            sa = v1.read_namespaced_service_account(username, "default")
                            print(f"[CLUSTER] Found ServiceAccount: {username}")
                            
                            # 获取 ServiceAccount 的 token
                            sa_secrets = v1.list_namespaced_secret(
                                "default",
                                field_selector=f"type=kubernetes.io/service-account-token"
                            )
                            sa_token = None
                            
                            for secret in sa_secrets.items:
                                if secret.metadata.annotations.get('kubernetes.io/service-account.name') == username:
                                    sa_token = base64.b64decode(secret.data['token']).decode('utf-8')
                                    print(f"[CLUSTER] Found token for ServiceAccount: {username}")
                                    break
                            
                            if sa_token:
                                print(f"[CLUSTER] Getting cluster information from: {kubeconfig}")
                                # 加载原始配置
                                config.load_kube_config(kubeconfig)
                                
                                # 获取集群信息
                                contexts, active_context = config.list_kube_config_contexts()
                                if not contexts:
                                    raise Exception("No contexts found in original kubeconfig")
                                
                                print(f"[CLUSTER] Found active context: {active_context['name']}")
                                
                                # 直接从 kubeconfig 文件读取完整配置
                                with open(kubeconfig) as f:
                                    kube_config = yaml.safe_load(f)
                                    print(f"[CLUSTER] Loaded original kubeconfig content")
                                
                                # 获取集群信息
                                cluster_info = None
                                for cluster in kube_config['clusters']:
                                    if cluster['name'] == active_context['context']['cluster']:
                                        cluster_info = cluster
                                        print(f"[CLUSTER] Found cluster info for: {cluster['name']}")
                                        break
                                
                                if not cluster_info:
                                    raise Exception(f"Cluster info not found for {active_context['context']['cluster']}")
                                
                                # 生成用户的 kubeconfig
                                print(f"[CLUSTER] Generating user kubeconfig using get_k8s_clients")
                                try:
                                    core_v1, apps_v1, networking_v1, batch_v1, dynamic_client = get_k8s_clients(kubeconfig, username)
                                    print(f"[CLUSTER] Successfully generated user kubeconfig")
                                    
                                    # 检查用户权限
                                    rbac = client.RbacAuthorizationV1Api()
                                    permissions = {
                                        "canViewLogs": True,
                                        "canExecPods": True,
                                        "canViewSecrets": True
                                    }
                                    
                                    cluster_access[cluster_name] = {
                                        "authenticated": True,
                                        "permissions": permissions
                                    }
                                except Exception as e:
                                    print(f"[CLUSTER] Error generating user kubeconfig: {e}")
                                    cluster_access[cluster_name] = {
                                        "authenticated": False,
                                        "error": "Error generating user kubeconfig",
                                        "error_details": str(e)
                                    }
                            else:
                                print(f"[CLUSTER] No token found for ServiceAccount {username}")
                                cluster_access[cluster_name] = {
                                    "authenticated": False,
                                    "error": "No ServiceAccount token found",
                                    "error_details": f"No token found for ServiceAccount {username}"
                                }
                                
                        except client.rest.ApiException as e:
                            if e.status == 404:
                                print(f"[CLUSTER] ServiceAccount {username} not found")
                                cluster_access[cluster_name] = {
                                    "authenticated": False,
                                    "error": "ServiceAccount not found",
                                    "error_details": f"ServiceAccount {username} not found"
                                }
                            else:
                                print(f"[CLUSTER] Error accessing ServiceAccount: {e}")
                                cluster_access[cluster_name] = {
                                    "authenticated": False,
                                    "error": "Error accessing ServiceAccount",
                                    "error_details": str(e)
                                }
                    else:
                        print(f"[CLUSTER] Invalid password for user {username} in cluster {cluster_name}")
                        cluster_access[cluster_name] = {
                            "authenticated": False,
                            "error": "Invalid password",
                            "error_details": "Password does not match"
                        }
                else:
                    print(f"[CLUSTER] No secret found for user {username} in cluster {cluster_name}")
                    cluster_access[cluster_name] = {
                        "authenticated": False,
                        "error": "User secret not found",
                        "error_details": f"No secret found for user {username}"
                    }
                    
            except Exception as e:
                print(f"[CLUSTER] Error checking user credentials: {e}")
                cluster_access[cluster_name] = {
                    "authenticated": False,
                    "error": "Error checking user credentials",
                    "error_details": str(e)
                }
                
        except Exception as e:
            print(f"[CLUSTER] Error accessing cluster {cluster_name}: {e}")
            cluster_access[cluster_name] = {
                "authenticated": False,
                "error": "Error accessing cluster",
                "error_details": str(e)
            }
        
        print(f"[CLUSTER] ========== Finished processing cluster: {cluster_name} ==========\n")
            
    print(f"[CLUSTER] Access check completed for user: {username}")
    print(f"[CLUSTER] Results summary:")
    for cluster_name, access in cluster_access.items():
        status = "✓ Authenticated" if access["authenticated"] else f"✗ Failed: {access['error']}"
        print(f"[CLUSTER] {cluster_name}: {status}")
    print(f"[CLUSTER] ========== Finished cluster access check for user: {username} ==========\n")
    
    return cluster_access

@app.post("/api/auth/login")
async def login(credentials: UserCredentials):
    try:
        print(f"[LOGIN] Login attempt for user: {credentials.username}")
        
        # 获取当前文件的绝对路径
        current_file = os.path.abspath(__file__)
        # 获取项目根目录
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        # 构建kubeconfig目录的路径
        kubeconfig_dir = os.path.join(project_root, "kubeconfig")
        
        print(f"[LOGIN] Project root: {project_root}")
        print(f"[LOGIN] Looking for kubeconfig files in: {kubeconfig_dir}")
        
        # 获取所有可用的集群配置
        available_clusters = []
        if os.path.exists(kubeconfig_dir):
            pattern_k8s = os.path.join(kubeconfig_dir, "k8s*")
            pattern_K8S = os.path.join(kubeconfig_dir, "K8S*")
            config_files = glob.glob(pattern_k8s) + glob.glob(pattern_K8S)
            available_clusters = [os.path.basename(f) for f in config_files]
            print(f"[LOGIN] Found clusters: {available_clusters}")
        
        if not available_clusters:
            print(f"[LOGIN] No clusters found in {kubeconfig_dir}")
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "No Kubernetes clusters configured",
                    "error_details": f"No kubeconfig files found in {kubeconfig_dir}"
                }
            )
        
        # 遍历所有集群，尝试验证
        auth_success = False
        auth_errors = {}
        authenticated_clusters = set()  # 使用集合来避免重复
        
        for cluster in available_clusters:
            try:
                print(f"\n[LOGIN] Trying authentication on cluster: {cluster}")
                config_path = os.path.join(kubeconfig_dir, cluster)
                
                # 使用原始kubeconfig加载配置
                config.load_kube_config(config_path)
                v1 = client.CoreV1Api()
                
                # 1. 验证用户Secret
                secret_name = f"user-credentials-{credentials.username}"
                print(f"[LOGIN] Looking for secret: {secret_name} in cluster {cluster}")
                
                try:
                    # 使用list_namespaced_secret而不是read_namespaced_secret
                    secrets = v1.list_namespaced_secret(
                        "default",
                        label_selector="app=k8s-resource-panel,type=user-credentials"
                    )
                    
                    user_secret = None
                    for secret in secrets.items:
                        if secret.metadata.name == secret_name:
                            user_secret = secret
                            print(f"[LOGIN] Found user secret: {secret_name} in cluster {cluster}")
                            break
                    
                    if user_secret:
                        # 验证密码
                        stored_password = base64.b64decode(user_secret.data.get('password', '')).decode('utf-8')
                        if stored_password == credentials.password:
                            print(f"[LOGIN] Password verified in cluster {cluster}")
                            
                            # 2. 验证ServiceAccount
                            sa_name = credentials.username
                            print(f"[LOGIN] Checking ServiceAccount: {sa_name} in cluster {cluster}")
                            sa = v1.read_namespaced_service_account(sa_name, "default")
                            print(f"[LOGIN] Found ServiceAccount: {sa_name} in cluster {cluster}")
                            
                            # 验证ServiceAccount的token是否存在
                            sa_secrets = v1.list_namespaced_secret(
                                "default",
                                field_selector=f"type=kubernetes.io/service-account-token"
                            )
                            
                            sa_token_found = False
                            for secret in sa_secrets.items:
                                if secret.metadata.annotations.get('kubernetes.io/service-account.name') == sa_name:
                                    sa_token_found = True
                                    print(f"[LOGIN] Found token for ServiceAccount: {sa_name} in cluster {cluster}")
                                    break
                            
                            if sa_token_found:
                                auth_success = True
                                authenticated_clusters.add(cluster)  # 使用add而不是append
                                print(f"[LOGIN] Authentication successful in cluster {cluster}")
                            else:
                                auth_errors[cluster] = "No ServiceAccount token found"
                        else:
                            auth_errors[cluster] = "Invalid password"
                    else:
                        auth_errors[cluster] = "User secret not found"
                        
                except Exception as e:
                    print(f"[LOGIN] Error in cluster {cluster}: {e}")
                    auth_errors[cluster] = str(e)
                    
            except Exception as e:
                print(f"[LOGIN] Error accessing cluster {cluster}: {e}")
                auth_errors[cluster] = str(e)
        
        if auth_success:
            # 设置基本权限
            permissions = {
                "canViewLogs": True,
                "canExecPods": True,
                "canViewSecrets": True
            }
            
            # 将集合转换为列表
            authenticated_cluster_list = list(authenticated_clusters)
            
            # 创建访问令牌
            access_token = create_access_token(
                data={
                    "sub": credentials.username,
                    "permissions": permissions,
                    "available_clusters": authenticated_cluster_list  # 使用转换后的列表
                }
            )
            
            print(f"[LOGIN] Successfully authenticated user: {credentials.username}")
            print(f"[LOGIN] Authenticated clusters: {authenticated_cluster_list}")
            return Token(
                access_token=access_token,
                token_type="bearer",
                permissions=permissions,
                available_clusters=authenticated_cluster_list  # 使用转换后的列表
            )
        else:
            print(f"[LOGIN] Authentication failed in all clusters")
            raise HTTPException(
                status_code=401,
                detail={
                    "message": "Authentication failed in all clusters",
                    "error_details": auth_errors
                }
            )
            
    except HTTPException as he:
        raise he
    except Exception as e:
        error_msg = f"Unexpected error during login"
        print(f"[LOGIN] {error_msg}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "message": error_msg,
                "error": str(e)
            }
        )

@app.get("/api/clusters")
async def get_clusters(current_user: dict = Depends(get_current_user)):
    """获取所有集群列表"""
    try:
        # 获取当前文件的绝对路径
        current_file = os.path.abspath(__file__)
        # 获取项目根目录
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        # 构建 kubeconfig 目录的路径
        kubeconfig_dir = os.path.join(project_root, "kubeconfig")
        
        if not os.path.exists(kubeconfig_dir):
            return {"clusters": []}
            
        # 获取所有 kubeconfig 文件名作为集群名
        all_clusters = [os.path.basename(f) for f in glob.glob(os.path.join(kubeconfig_dir, "*"))]
        
        # 获取用户有权限的集群列表
        username = current_user.get("sub")
        authorized_clusters = set()  # 使用集合来避免重复
        
        for cluster in all_clusters:
            try:
                # 加载集群配置
                cluster_config_path = os.path.join(kubeconfig_dir, cluster)
                config.load_kube_config(cluster_config_path)
                v1 = client.CoreV1Api()
                
                # 检查用户的 secret 是否存在
                secret_name = f"user-credentials-{username}"
                secrets = v1.list_namespaced_secret(
                    "default",
                    label_selector="app=k8s-resource-panel,type=user-credentials"
                )
                
                # 查找用户对应的 secret
                user_secret = None
                for secret in secrets.items:
                    if secret.metadata.name == secret_name:
                        # 验证 secret 中的凭证
                        try:
                            secret_data = secret.data
                            if not secret_data or 'username' not in secret_data or 'password' not in secret_data:
                                print(f"[CLUSTERS] Invalid secret data for user {username} in cluster {cluster}")
                                continue
                                
                            # 检查 ServiceAccount 是否存在并有效
                            try:
                                sa = v1.read_namespaced_service_account(username, "default")
                                # 检查 ServiceAccount token 是否存在
                                sa_secrets = v1.list_namespaced_secret(
                                    "default",
                                    field_selector=f"type=kubernetes.io/service-account-token"
                                )
                                for sa_secret in sa_secrets.items:
                                    if sa_secret.metadata.annotations.get('kubernetes.io/service-account.name') == username:
                                        authorized_clusters.add(cluster)  # 使用add而不是append
                                        print(f"[CLUSTERS] Added authorized cluster: {cluster}")
                                        break
                            except client.rest.ApiException as e:
                                print(f"[CLUSTERS] Error checking ServiceAccount for user {username} in cluster {cluster}: {e}")
                                continue
                        except Exception as e:
                            print(f"[CLUSTERS] Error validating secret for user {username} in cluster {cluster}: {e}")
                            continue
                        break
            except Exception as e:
                print(f"[CLUSTERS] Error checking cluster {cluster}: {e}")
                continue
        
        # 将集合转换为列表返回
        return {"clusters": list(authorized_clusters)}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": f"获取集群列表失败: {str(e)}"}
        )

@app.get("/api/clusters/available")
async def get_available_clusters(current_user: dict = Depends(get_current_user)):
    """获取用户可用的集群列表（已有 kubeconfig 的集群）"""
    try:
        # 获取当前文件的绝对路径
        current_file = os.path.abspath(__file__)
        # 获取项目根目录
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        # 构建用户 kubeconfig 目录的路径
        user_kubeconfig_dir = os.path.join(project_root, "user_kubeconfig", current_user["sub"])
        print(f"[CLUSTERS] Checking available clusters in: {user_kubeconfig_dir}")
        
        available_clusters = []
        
        # 如果目录存在，遍历所有 kubeconfig 文件
        if os.path.exists(user_kubeconfig_dir):
            for filename in os.listdir(user_kubeconfig_dir):
                if filename.endswith('.yaml'):
                    cluster_name = filename.replace('.yaml', '')
                    available_clusters.append(cluster_name)
                    print(f"[CLUSTERS] Found cluster: {cluster_name}")
        
        print(f"[CLUSTERS] Total available clusters: {len(available_clusters)}")
        return {"clusters": available_clusters}
    except Exception as e:
        print(f"[CLUSTERS] Error getting available clusters: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={"message": f"获取可用集群列表失败: {str(e)}"}
        )

def load_all_configs():
    """加载所有kubeconfig文件"""
    configs = {}
    
    # 获取当前文件的绝对路径
    current_file = os.path.abspath(__file__)
    print(f"[CONFIG] Current file path: {current_file}")
    
    # 获取项目根目录
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    print(f"[CONFIG] Project root: {project_root}")
    
    # 构建kubeconfig目录的路径
    kubeconfig_dir = os.path.join(project_root, "kubeconfig")
    print(f"[CONFIG] Kubeconfig directory: {kubeconfig_dir}")
    
    if not os.path.exists(kubeconfig_dir):
        print(f"[CONFIG] Kubeconfig directory does not exist: {kubeconfig_dir}")
        return configs
    
    # 获取所有文件
    config_files = os.listdir(kubeconfig_dir)
    print(f"[CONFIG] Found {len(config_files)} files in kubeconfig directory")
    
    for filename in config_files:
        config_path = os.path.join(kubeconfig_dir, filename)
        print(f"[CONFIG] Processing config file: {config_path}")
        
        # 检查文件是否为文件而非目录
        if not os.path.isfile(config_path):
            print(f"[CONFIG] Skipping non-file: {config_path}")
            continue
            
        # 检查文件大小
        file_size = os.path.getsize(config_path)
        print(f"[CONFIG] File size: {file_size} bytes")
        
        if file_size == 0:
            print(f"[CONFIG] Skipping empty file: {config_path}")
            continue
            
        try:
            # 尝试读取 YAML 文件
            print(f"[CONFIG] Attempting to parse YAML file: {config_path}")
            with open(config_path, 'r') as f:
                try:
                    yaml_content = yaml.safe_load(f)
                    print(f"[CONFIG] Successfully loaded YAML content")
                    
                    # 检查文件内容格式
                    if not isinstance(yaml_content, dict):
                        print(f"[CONFIG] Invalid YAML format: not a dictionary in {config_path}")
                        continue
                        
                    if 'kind' not in yaml_content or yaml_content['kind'] != 'Config':
                        print(f"[CONFIG] Not a Kubernetes config file: missing or incorrect 'kind' in {config_path}")
                        print(f"[CONFIG] Content keys: {list(yaml_content.keys())}")
                        if 'kind' in yaml_content:
                            print(f"[CONFIG] Kind value: {yaml_content['kind']}")
                        continue
                        
                    # 尝试验证 kubeconfig 文件
                    try:
                        print(f"[CONFIG] Validating kubeconfig file: {config_path}")
                        temp_file = tempfile.NamedTemporaryFile(delete=False)
                        try:
                            with open(config_path, 'r') as src:
                                temp_file.write(src.read().encode('utf-8'))
                            temp_file.close()
                            
                            config.load_kube_config(temp_file.name)
                            client.CoreV1Api()  # 尝试创建API客户端
                            print(f"[CONFIG] Successfully validated kubeconfig: {config_path}")
                            
                            configs[filename] = config_path
                            print(f"[CONFIG] Added config for cluster: {filename}")
                        finally:
                            os.unlink(temp_file.name)
                    except Exception as e:
                        print(f"[CONFIG] Error validating kubeconfig {config_path}: {e}")
                        
                except yaml.YAMLError as e:
                    print(f"[CONFIG] Error parsing YAML in {config_path}: {e}")
        except Exception as e:
            print(f"[CONFIG] Error processing file {config_path}: {e}")
    
    print(f"[CONFIG] Total clusters loaded: {len(configs)}")
    return configs

def get_user_kubeconfig_path(username: str, cluster_name: str) -> str:
    """获取用户特定的 kubeconfig 文件路径"""
    # 获取当前文件的绝对路径
    current_file = os.path.abspath(__file__)
    print(f"[KUBECONFIG_PATH] Current file path: {current_file}")
    
    # 获取项目根目录
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    print(f"[KUBECONFIG_PATH] Project root: {project_root}")
    
    # 构建用户配置目录路径
    user_kubeconfig_dir = os.path.join(project_root, "user_kubeconfig", username)
    print(f"[KUBECONFIG_PATH] User kubeconfig directory: {user_kubeconfig_dir}")
    
    # 确保目录存在
    try:
        os.makedirs(user_kubeconfig_dir, exist_ok=True)
        print(f"[KUBECONFIG_PATH] Created/verified user kubeconfig directory: {user_kubeconfig_dir}")
    except Exception as e:
        error_msg = f"创建用户目录失败: {str(e)}"
        print(f"[KUBECONFIG_PATH] Error: {error_msg}")
        print(f"[KUBECONFIG_PATH] Exception: {e}")
        raise Exception(error_msg)
    
    # 构建配置文件路径
    config_path = os.path.join(user_kubeconfig_dir, f"{cluster_name}.yaml")
    print(f"[KUBECONFIG_PATH] User kubeconfig file path: {config_path}")
    
    return config_path

def get_k8s_clients(kubeconfig_path: str, username: str = None):
    """获取k8s客户端"""
    try:
        print(f"\n[KUBECONFIG] ========== Starting get_k8s_clients ==========")
        print(f"[KUBECONFIG] Using kubeconfig: {kubeconfig_path}")
        print(f"[KUBECONFIG] Username: {username}")
        
        # 检查kubeconfig文件是否存在
        if not os.path.exists(kubeconfig_path):
            print(f"[KUBECONFIG] Kubeconfig file not found: {kubeconfig_path}")
            if username:
                print(f"[KUBECONFIG] User kubeconfig not found, returning None")
                return None, None, None, None, None
            raise Exception(f"Kubeconfig file not found: {kubeconfig_path}")
            
        # 检查kubeconfig文件是否为空
        if os.path.getsize(kubeconfig_path) == 0:
            print(f"[KUBECONFIG] Kubeconfig file is empty: {kubeconfig_path}")
            if username:
                print(f"[KUBECONFIG] User kubeconfig is empty, returning None")
                return None, None, None, None, None
            raise Exception(f"Kubeconfig file is empty: {kubeconfig_path}")
            
        # 首先读取并验证kubeconfig文件
        print(f"[KUBECONFIG] Reading and validating kubeconfig file")
        with open(kubeconfig_path) as f:
            kube_config = yaml.safe_load(f)
            print(f"[KUBECONFIG] Successfully loaded kubeconfig content")
            
            if not isinstance(kube_config, dict):
                print(f"[KUBECONFIG] Invalid kubeconfig format: not a dictionary")
                if username:
                    print(f"[KUBECONFIG] User kubeconfig is invalid, returning None")
                    return None, None, None, None, None
                raise Exception("Invalid kubeconfig format: not a dictionary")
                
            # 验证必需的字段
            required_fields = ['apiVersion', 'kind', 'clusters', 'contexts', 'current-context', 'users']
            missing_fields = [field for field in required_fields if field not in kube_config]
            if missing_fields:
                print(f"[KUBECONFIG] Missing required fields: {missing_fields}")
                if username:
                    print(f"[KUBECONFIG] User kubeconfig is missing fields, returning None")
                    return None, None, None, None, None
                raise Exception(f"Missing required fields in kubeconfig: {', '.join(missing_fields)}")
                
            # 验证用户凭证
            if not kube_config.get('users'):
                print(f"[KUBECONFIG] No users found in kubeconfig")
                if username:
                    print(f"[KUBECONFIG] User kubeconfig has no users, returning None")
                    return None, None, None, None, None
                raise Exception("No users found in kubeconfig")
                
            # 检查用户凭证中的 token
            user_entry = kube_config['users'][0]
            if 'user' not in user_entry or 'token' not in user_entry['user']:
                print(f"[KUBECONFIG] No token found in user credentials")
                if username:
                    print(f"[KUBECONFIG] User kubeconfig has no token, returning None")
                    return None, None, None, None, None
                raise Exception("No token found in user credentials")
                
            # 检查 token 是否为空
            if not user_entry['user']['token']:
                print(f"[KUBECONFIG] Token is empty")
                if username:
                    print(f"[KUBECONFIG] User kubeconfig has empty token, returning None")
                    return None, None, None, None, None
                raise Exception("Token is empty")
                
            print(f"[KUBECONFIG] Token validation passed")
            
        # 加载kubeconfig
        print(f"[KUBECONFIG] Loading kubeconfig")
        config.load_kube_config(kubeconfig_path)
        
        # 获取上下文信息
        print(f"[KUBECONFIG] Getting context information")
        contexts, active_context = config.list_kube_config_contexts()
        if not contexts:
            print(f"[KUBECONFIG] No contexts found")
            if username:
                print(f"[KUBECONFIG] User kubeconfig has no valid contexts, returning None")
                return None, None, None, None, None
            raise Exception("No contexts found in kubeconfig")
            
        # 获取当前集群的配置
        cluster_name = active_context['name']
        print(f"[KUBECONFIG] Active context name: {cluster_name}")
        
        # 获取集群信息
        cluster_info = None
        for cluster in kube_config['clusters']:
            if cluster['name'] == active_context['context']['cluster']:
                cluster_info = cluster
                print(f"[KUBECONFIG] Found cluster info for: {cluster['name']}")
                break
                
        if not cluster_info:
            print(f"[KUBECONFIG] No cluster info found")
            if username:
                print(f"[KUBECONFIG] User kubeconfig has no valid cluster info, returning None")
                return None, None, None, None, None
            raise Exception(f"Cluster info not found for {active_context['context']['cluster']}")
        
        print(f"[KUBECONFIG] Creating API clients")
        api_client = ApiClient()
        dynamic_client = dynamic.DynamicClient(api_client)
        
        # 创建并测试客户端
        core_v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        networking_v1 = client.NetworkingV1Api()
        batch_v1 = client.BatchV1Api()
        
        # 测试连接
        try:
            print(f"[KUBECONFIG] Testing API connection")
            core_v1.list_namespace(_request_timeout=5)
            print(f"[KUBECONFIG] API connection test passed")
        except Exception as e:
            print(f"[KUBECONFIG] API connection test failed: {e}")
            if username:
                print(f"[KUBECONFIG] Returning None due to API test failure")
                return None, None, None, None, None
            raise Exception(f"API connection test failed: {str(e)}")
        
        print(f"[KUBECONFIG] Successfully created API clients")
        print(f"[KUBECONFIG] ========== Finished get_k8s_clients ==========\n")
        return (
            core_v1,
            apps_v1,
            networking_v1,
            batch_v1,
            dynamic_client
        )
    except Exception as e:
        print(f"[KUBECONFIG] Error in get_k8s_clients: {e}")
        if username:
            print(f"[KUBECONFIG] Returning None due to error for user kubeconfig")
            return None, None, None, None, None
        raise HTTPException(status_code=500, detail=f"Failed to load kubeconfig: {str(e)}")

@app.get("/api/resources/{cluster}")
async def get_cluster_resources(cluster: str, token: str = Depends(oauth2_scheme)):
    """获取指定集群的所有资源"""
    try:
        print(f"\n[RESOURCES] ========== Getting resources for cluster: {cluster} ==========")
        
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        print(f"[RESOURCES] User: {username}")
        
        # 获取用户的 kubeconfig 路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        print(f"[RESOURCES] User kubeconfig path: {user_config_path}")
        
        if not os.path.exists(user_config_path):
            print(f"[RESOURCES] Error: Kubeconfig not found at {user_config_path}")
            raise HTTPException(
                status_code=404,
                detail={"message": "未找到用户的 kubeconfig 配置文件，请先生成配置"}
            )
            
        try:
            print(f"[RESOURCES] Loading kubeconfig from: {user_config_path}")
            # 读取并验证 kubeconfig 内容
            with open(user_config_path) as f:
                kube_config = yaml.safe_load(f)
                print(f"[RESOURCES] Successfully loaded kubeconfig content")
                
                if not isinstance(kube_config, dict):
                    raise ValueError("Invalid kubeconfig format: not a dictionary")
                    
                required_fields = ['apiVersion', 'kind', 'clusters', 'contexts', 'current-context', 'users']
                missing_fields = [field for field in required_fields if field not in kube_config]
                if missing_fields:
                    raise ValueError(f"Missing required fields in kubeconfig: {', '.join(missing_fields)}")
                    
                # 检查用户凭证
                if not kube_config.get('users'):
                    raise ValueError("No user credentials found in kubeconfig")
                    
                user_entry = kube_config['users'][0]
                if 'user' not in user_entry or 'token' not in user_entry['user']:
                    raise ValueError("No token found in user credentials")
                    
                print(f"[RESOURCES] Kubeconfig validation passed")
            
            # 使用用户的 kubeconfig
            config.load_kube_config(user_config_path)
            print(f"[RESOURCES] Successfully loaded kubeconfig")
            
            # 创建新的 API 客户端
            core_v1 = client.CoreV1Api()
            apps_v1 = client.AppsV1Api()
            networking_v1 = client.NetworkingV1Api()
            batch_v1 = client.BatchV1Api()
            api_client = ApiClient()
            dynamic_client = dynamic.DynamicClient(api_client)
            print(f"[RESOURCES] Successfully created API clients")
            
            # 测试连接
            try:
                print(f"[RESOURCES] Testing API connection")
                core_v1.list_namespace(_request_timeout=5)
                print(f"[RESOURCES] API connection test passed")
            except Exception as e:
                print(f"[RESOURCES] API connection test failed: {e}")
                raise HTTPException(
                    status_code=401,
                    detail={"message": f"API 连接测试失败，请刷新配置: {str(e)}"}
                )
            
            # 获取各种资源
            resources = {
                "nodes": [],
                "pods": [],
                "deployments": [],
                "services": [],
                "ingresses": [],
                "gateways": [],
                "virtualservices": [],
                "jobs": [],
                "cronjobs": []
            }
            
            # 获取节点信息
            try:
                print(f"[RESOURCES] Fetching nodes")
                nodes = core_v1.list_node()
                for node in nodes.items:
                    resources["nodes"].append({
                        "name": node.metadata.name,
                        "status": node.status.conditions[-1].type if node.status.conditions else "Unknown",
                        "kubelet_version": node.status.node_info.kubelet_version
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching nodes: {e}")
            
            # 获取所有命名空间的Pod
            try:
                print(f"[RESOURCES] Fetching pods")
                pods = core_v1.list_pod_for_all_namespaces()
                for pod in pods.items:
                    # Get container information
                    containers = []
                    init_containers = []
                    
                    # Get init containers
                    if pod.spec.init_containers:
                        for container in pod.spec.init_containers:
                            container_status = next(
                                (status for status in pod.status.init_container_statuses 
                                 if status.name == container.name),
                                None
                            )
                            init_containers.append({
                                "name": container.name,
                                "image": container.image,
                                "status": "Running" if container_status and container_status.state.running 
                                         else "Waiting" if container_status and container_status.state.waiting
                                         else "Terminated" if container_status and container_status.state.terminated
                                         else "Unknown"
                            })
                    
                    # Get main containers
                    if pod.spec.containers:
                        for container in pod.spec.containers:
                            container_status = next(
                                (status for status in pod.status.container_statuses 
                                 if status.name == container.name),
                                None
                            )
                            containers.append({
                                "name": container.name,
                                "image": container.image,
                                "status": "Running" if container_status and container_status.state.running 
                                         else "Waiting" if container_status and container_status.state.waiting
                                         else "Terminated" if container_status and container_status.state.terminated
                                         else "Unknown"
                            })
                    
                    resources["pods"].append({
                        "name": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "status": pod.status.phase,
                        "node": pod.spec.node_name if pod.spec.node_name else "Unknown",
                        "containers": containers,
                        "init_containers": init_containers
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching pods: {e}")
            
            # 获取所有命名空间的Deployment
            try:
                print(f"[RESOURCES] Fetching deployments")
                deployments = apps_v1.list_deployment_for_all_namespaces()
                for dep in deployments.items:
                    resources["deployments"].append({
                        "name": dep.metadata.name,
                        "namespace": dep.metadata.namespace,
                        "replicas": f"{dep.status.ready_replicas or 0}/{dep.spec.replicas}"
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching deployments: {e}")
            
            # 获取所有命名空间的Service
            try:
                print(f"[RESOURCES] Fetching services")
                services = core_v1.list_service_for_all_namespaces()
                for svc in services.items:
                    resources["services"].append({
                        "name": svc.metadata.name,
                        "namespace": svc.metadata.namespace,
                        "type": svc.spec.type,
                        "cluster_ip": svc.spec.cluster_ip
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching services: {e}")
            
            # 获取所有命名空间的Ingress
            try:
                print(f"[RESOURCES] Fetching ingresses")
                ingresses = networking_v1.list_ingress_for_all_namespaces()
                for ing in ingresses.items:
                    resources["ingresses"].append({
                        "name": ing.metadata.name,
                        "namespace": ing.metadata.namespace,
                        "hosts": [rule.host for rule in ing.spec.rules] if ing.spec.rules else []
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching ingresses: {e}")

            # 获取Istio Gateway
            try:
                print(f"[RESOURCES] Fetching gateways")
                gateway_api = dynamic_client.resources.get(
                    api_version="networking.istio.io/v1beta1",
                    kind="Gateway"
                )
                gateways = gateway_api.get()
                for gw in gateways.items:
                    resources["gateways"].append({
                        "name": gw["metadata"]["name"],
                        "namespace": gw["metadata"]["namespace"],
                        "servers": len(gw["spec"].get("servers", [])) if "spec" in gw else 0
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching gateways: {e}")

            # 获取Istio VirtualService
            try:
                print(f"[RESOURCES] Fetching virtual services")
                vs_api = dynamic_client.resources.get(
                    api_version="networking.istio.io/v1beta1",
                    kind="VirtualService"
                )
                virtual_services = vs_api.get()
                for vs in virtual_services.items:
                    resources["virtualservices"].append({
                        "name": vs["metadata"]["name"],
                        "namespace": vs["metadata"]["namespace"],
                        "gateways": vs["spec"].get("gateways", []) if "spec" in vs else [],
                        "hosts": vs["spec"].get("hosts", []) if "spec" in vs else []
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching virtual services: {e}")
            
            # 获取所有命名空间的Job
            try:
                print(f"[RESOURCES] Fetching jobs")
                jobs = batch_v1.list_job_for_all_namespaces()
                for job in jobs.items:
                    resources["jobs"].append({
                        "name": job.metadata.name,
                        "namespace": job.metadata.namespace,
                        "status": "Completed" if job.status.succeeded else "Active" if job.status.active else "Failed"
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching jobs: {e}")
            
            # 获取所有命名空间的CronJob
            try:
                print(f"[RESOURCES] Fetching cronjobs")
                cronjobs = batch_v1.list_cron_job_for_all_namespaces()
                for cronjob in cronjobs.items:
                    resources["cronjobs"].append({
                        "name": cronjob.metadata.name,
                        "namespace": cronjob.metadata.namespace,
                        "schedule": cronjob.spec.schedule
                    })
            except Exception as e:
                print(f"[RESOURCES] Error fetching cronjobs: {e}")
            
            print(f"[RESOURCES] Successfully fetched all resources")
            print(f"[RESOURCES] ========== Finished getting resources for cluster: {cluster} ==========\n")
            return resources
            
        except ValueError as ve:
            print(f"[RESOURCES] Validation error: {ve}")
            raise HTTPException(
                status_code=400,
                detail={"message": f"Kubeconfig 验证失败: {str(ve)}"}
            )
        except client.rest.ApiException as e:
            print(f"[RESOURCES] Kubernetes API error: {e}")
            if e.status == 401:
                raise HTTPException(
                    status_code=401,
                    detail={"message": f"认证失败，请刷新配置: {str(e)}"}
                )
            raise HTTPException(
                status_code=e.status,
                detail={"message": f"获取集群资源失败: {str(e)}"}
            )
            
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"[RESOURCES] Unexpected error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"message": f"获取集群资源失败: {str(e)}"}
        )

@app.get("/api/resources/{cluster}/{resource_type}")
async def get_cluster_resource_type(cluster: str, resource_type: str, token: str = Depends(oauth2_scheme)):
    """获取指定集群的特定资源类型"""
    try:
        print(f"\n[RESOURCES] ========== Getting {resource_type} for cluster: {cluster} ==========")
        
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        print(f"[RESOURCES] User: {username}")
        
        # 获取用户的 kubeconfig 路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        print(f"[RESOURCES] User kubeconfig path: {user_config_path}")
        
        if not os.path.exists(user_config_path):
            print(f"[RESOURCES] Error: Kubeconfig not found at {user_config_path}")
            raise HTTPException(
                status_code=404,
                detail={"message": "未找到用户的 kubeconfig 配置文件，请先生成配置"}
            )
            
        # 读取并验证 kubeconfig 内容
        print(f"[RESOURCES] Reading kubeconfig content")
        try:
            with open(user_config_path) as f:
                kube_config = yaml.safe_load(f)
                print(f"[RESOURCES] Successfully loaded kubeconfig content")
                
                # 打印关键信息用于调试
                print(f"[RESOURCES] API Server: {kube_config['clusters'][0]['cluster']['server']}")
                print(f"[RESOURCES] Current Context: {kube_config['current-context']}")
                print(f"[RESOURCES] User: {kube_config['users'][0]['name']}")
                print(f"[RESOURCES] Token exists: {bool(kube_config['users'][0]['user'].get('token'))}")
                if kube_config['users'][0]['user'].get('token'):
                    token_length = len(kube_config['users'][0]['user']['token'])
                    print(f"[RESOURCES] Token length: {token_length}")
                    print(f"[RESOURCES] Token prefix: {kube_config['users'][0]['user']['token'][:10]}...")
        except Exception as e:
            print(f"[RESOURCES] Error reading kubeconfig: {e}")
            raise HTTPException(
                status_code=500,
                detail={"message": f"读取 kubeconfig 失败: {str(e)}"}
            )
            
        # 加载 kubeconfig
        print(f"[RESOURCES] Loading kubeconfig")
        config.load_kube_config(user_config_path)
        print(f"[RESOURCES] Successfully loaded kubeconfig")
        
        # 创建 API 客户端
        core_v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        networking_v1 = client.NetworkingV1Api()
        batch_v1 = client.BatchV1Api()
        api_client = ApiClient()
        dynamic_client = dynamic.DynamicClient(api_client)
        print(f"[RESOURCES] Successfully created API clients")
        
        resources = []
        print(f"[RESOURCES] Fetching resource type: {resource_type}")
        
        try:
            if resource_type == "nodes":
                nodes = core_v1.list_node()
                for node in nodes.items:
                    resources.append({
                        "name": node.metadata.name,
                        "status": node.status.conditions[-1].type if node.status.conditions else "Unknown",
                        "kubelet_version": node.status.node_info.kubelet_version
                    })
                    
            elif resource_type == "pods":
                pods = core_v1.list_pod_for_all_namespaces()
                for pod in pods.items:
                    # Get container information
                    containers = []
                    init_containers = []
                    
                    # Get init containers
                    if pod.spec.init_containers:
                        for container in pod.spec.init_containers:
                            container_status = next(
                                (status for status in pod.status.init_container_statuses 
                                 if status.name == container.name),
                                None
                            )
                            init_containers.append({
                                "name": container.name,
                                "image": container.image,
                                "status": "Running" if container_status and container_status.state.running 
                                         else "Waiting" if container_status and container_status.state.waiting
                                         else "Terminated" if container_status and container_status.state.terminated
                                         else "Unknown"
                            })
                    
                    # Get main containers
                    if pod.spec.containers:
                        for container in pod.spec.containers:
                            container_status = next(
                                (status for status in pod.status.container_statuses 
                                 if status.name == container.name),
                                None
                            )
                            containers.append({
                                "name": container.name,
                                "image": container.image,
                                "status": "Running" if container_status and container_status.state.running 
                                         else "Waiting" if container_status and container_status.state.waiting
                                         else "Terminated" if container_status and container_status.state.terminated
                                         else "Unknown"
                            })
                    
                    resources.append({
                        "name": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "status": pod.status.phase,
                        "node": pod.spec.node_name if pod.spec.node_name else "Unknown",
                        "containers": containers,
                        "init_containers": init_containers
                    })
                    
            elif resource_type == "deployments":
                deployments = apps_v1.list_deployment_for_all_namespaces()
                for dep in deployments.items:
                    resources.append({
                        "name": dep.metadata.name,
                        "namespace": dep.metadata.namespace,
                        "replicas": f"{dep.status.ready_replicas or 0}/{dep.spec.replicas}"
                    })
                    
            elif resource_type == "services":
                services = core_v1.list_service_for_all_namespaces()
                for svc in services.items:
                    resources.append({
                        "name": svc.metadata.name,
                        "namespace": svc.metadata.namespace,
                        "type": svc.spec.type,
                        "cluster_ip": svc.spec.cluster_ip
                    })
                    
            elif resource_type == "ingresses":
                ingresses = networking_v1.list_ingress_for_all_namespaces()
                for ing in ingresses.items:
                    resources.append({
                        "name": ing.metadata.name,
                        "namespace": ing.metadata.namespace,
                        "hosts": [rule.host for rule in ing.spec.rules] if ing.spec.rules else []
                    })

            elif resource_type == "gateways":
                gateway_api = dynamic_client.resources.get(
                    api_version="networking.istio.io/v1beta1",
                    kind="Gateway"
                )
                gateways = gateway_api.get()
                for gw in gateways.items:
                    resources.append({
                        "name": gw["metadata"]["name"],
                        "namespace": gw["metadata"]["namespace"],
                        "servers": len(gw["spec"].get("servers", [])) if "spec" in gw else 0
                    })

            elif resource_type == "virtualservices":
                vs_api = dynamic_client.resources.get(
                    api_version="networking.istio.io/v1beta1",
                    kind="VirtualService"
                )
                virtual_services = vs_api.get()
                for vs in virtual_services.items:
                    resources.append({
                        "name": vs["metadata"]["name"],
                        "namespace": vs["metadata"]["namespace"],
                        "gateways": vs["spec"].get("gateways", []) if "spec" in vs else [],
                        "hosts": vs["spec"].get("hosts", []) if "spec" in vs else []
                    })
                    
            elif resource_type == "jobs":
                jobs = batch_v1.list_job_for_all_namespaces()
                for job in jobs.items:
                    resources.append({
                        "name": job.metadata.name,
                        "namespace": job.metadata.namespace,
                        "status": "Completed" if job.status.succeeded else "Active" if job.status.active else "Failed"
                    })
                    
            elif resource_type == "cronjobs":
                cronjobs = batch_v1.list_cron_job_for_all_namespaces()
                for cronjob in cronjobs.items:
                    resources.append({
                        "name": cronjob.metadata.name,
                        "namespace": cronjob.metadata.namespace,
                        "schedule": cronjob.spec.schedule
                    })
                    
        except client.rest.ApiException as e:
            print(f"[RESOURCES] API error fetching {resource_type}: {e}")
            if e.status == 401:
                print(f"[RESOURCES] Authentication failed. Token details:")
                try:
                    with open(user_config_path) as f:
                        current_config = yaml.safe_load(f)
                        if current_config and 'users' in current_config and current_config['users']:
                            token = current_config['users'][0]['user'].get('token', '')
                            print(f"[RESOURCES] Token length: {len(token)}")
                            print(f"[RESOURCES] Token prefix: {token[:10] if token else 'None'}")
                except Exception as read_error:
                    print(f"[RESOURCES] Error reading current config: {read_error}")
                raise HTTPException(
                    status_code=401,
                    detail={"message": f"认证失败，请刷新配置。错误: {str(e)}"}
                )
            raise HTTPException(
                status_code=e.status,
                detail={"message": f"获取资源失败: {str(e)}"}
            )
        except Exception as e:
            print(f"[RESOURCES] Error fetching {resource_type}: {e}")
            raise HTTPException(
                status_code=500,
                detail={"message": f"获取资源失败: {str(e)}"}
            )
        
        print(f"[RESOURCES] Successfully fetched {resource_type}")
        print(f"[RESOURCES] ========== Finished getting {resource_type} for cluster: {cluster} ==========\n")
        return resources
        
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"[RESOURCES] Unexpected error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"message": f"获取资源失败: {str(e)}"}
        )

@app.get("/api/resources/{cluster}/secrets")
async def get_secrets(cluster: str, token: str = Depends(oauth2_scheme)):
    try:
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        if not user["permissions"].get("canViewSecrets"):
            raise HTTPException(status_code=403, detail="No permission to view secrets")

        # 获取用户的 kubeconfig 路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        if not os.path.exists(user_config_path):
            raise HTTPException(
                status_code=404,
                detail={"message": "未找到用户的 kubeconfig 配置文件，请先生成配置"}
            )

        # 使用用户的 kubeconfig
        config.load_kube_config(user_config_path)
        core_v1 = client.CoreV1Api()
        
        try:
            secrets = core_v1.list_secret_for_all_namespaces()
            
            result = []
            for secret in secrets.items:
                secret_info = {
                    "name": secret.metadata.name,
                    "namespace": secret.metadata.namespace,
                    "type": secret.type,
                    "created": secret.metadata.creation_timestamp.isoformat()
                }
                
                # Check for TLS secrets
                if secret.type == "kubernetes.io/tls" and "tls.crt" in secret.data:
                    try:
                        cert_data = base64.b64decode(secret.data["tls.crt"]).decode()
                        tls_info = parse_tls_certificate(cert_data)
                        if tls_info:
                            secret_info.update({
                                "tls_expiration": tls_info["expiration"],
                                "days_until_expiry": tls_info["days_until_expiry"],
                                "is_expired": tls_info["is_expired"]
                            })
                    except Exception as e:
                        print(f"Error processing TLS secret {secret.metadata.name}: {e}")
                
                result.append(secret_info)
            
            return result
            
        except client.rest.ApiException as e:
            if e.status == 403:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "message": "Permission denied",
                        "error_details": "You don't have permission to list secrets"
                    }
                )
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Failed to list secrets",
                    "error_details": str(e)
                }
            )
            
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Failed to get secrets",
                "error_details": str(e)
            }
        )

@app.get("/api/resources/{cluster}/serviceaccounts")
async def get_serviceaccounts(cluster: str, token: str = Depends(oauth2_scheme)):
    try:
        config.load_kube_config(os.path.join("kubeconfig", cluster))
        v1 = client.CoreV1Api()
        serviceaccounts = v1.list_service_account_for_all_namespaces()
        return [
            {
                "name": sa.metadata.name,
                "namespace": sa.metadata.namespace,
                "created": sa.metadata.creation_timestamp.isoformat()
            }
            for sa in serviceaccounts.items
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/resources/{cluster}/clusterroles")
async def get_clusterroles(cluster: str, token: str = Depends(oauth2_scheme)):
    try:
        config.load_kube_config(os.path.join("kubeconfig", cluster))
        rbac = client.RbacAuthorizationV1Api()
        roles = rbac.list_cluster_role()
        return [
            {
                "name": role.metadata.name,
                "created": role.metadata.creation_timestamp.isoformat()
            }
            for role in roles.items
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/resources/{cluster}/clusterrolebindings")
async def get_clusterrolebindings(cluster: str, token: str = Depends(oauth2_scheme)):
    try:
        config.load_kube_config(os.path.join("kubeconfig", cluster))
        rbac = client.RbacAuthorizationV1Api()
        bindings = rbac.list_cluster_role_binding()
        return [
            {
                "name": binding.metadata.name,
                "roleRef": binding.role_ref.name,
                "subjects": [
                    {
                        "kind": subject.kind,
                        "name": subject.name,
                        "namespace": subject.namespace
                    }
                    for subject in binding.subjects
                ]
            }
            for binding in bindings.items
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/resources/{cluster}/configmaps")
async def get_configmaps(cluster: str, token: str = Depends(oauth2_scheme)):
    try:
        config.load_kube_config(os.path.join("kubeconfig", cluster))
        v1 = client.CoreV1Api()
        configmaps = v1.list_config_map_for_all_namespaces()
        return [
            {
                "name": cm.metadata.name,
                "namespace": cm.metadata.namespace,
                "dataKeys": list(cm.data.keys()) if cm.data else []
            }
            for cm in configmaps.items
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/kubeconfig/{cluster}/refresh")
async def refresh_kubeconfig(cluster: str, token: str = Depends(oauth2_scheme)):
    """手动刷新指定集群的 kubeconfig"""
    try:
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        
        print(f"[KUBECONFIG] Manual refresh requested for cluster {cluster} by user {username}")
        
        configs = load_all_configs()
        if cluster not in configs:
            raise HTTPException(status_code=404, detail="Cluster not found")
            
        kubeconfig_path = configs[cluster]
        print(f"[KUBECONFIG] Using kubeconfig path: {kubeconfig_path}")
        
        try:
            # 使用 get_k8s_clients 生成新的 kubeconfig
            core_v1, apps_v1, networking_v1, batch_v1, dynamic_client = get_k8s_clients(kubeconfig_path, username)
            print(f"[KUBECONFIG] Successfully refreshed kubeconfig for cluster {cluster}")
            
            # 获取生成的 kubeconfig 文件路径
            user_config_path = get_user_kubeconfig_path(username, cluster)
            
            if os.path.exists(user_config_path):
                file_size = os.path.getsize(user_config_path)
                print(f"[KUBECONFIG] Verified refreshed kubeconfig exists with size: {file_size} bytes")
                return {"message": "Successfully refreshed kubeconfig", "status": "success"}
            else:
                raise HTTPException(status_code=500, detail="Failed to generate kubeconfig file")
                
        except Exception as e:
            print(f"[KUBECONFIG] Error refreshing kubeconfig: {e}")
            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Failed to refresh kubeconfig",
                    "error": str(e)
                }
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/kubeconfig/{cluster}/generate")
async def generate_kubeconfig(cluster: str, token: str = Depends(oauth2_scheme)):
    """生成用户的 kubeconfig 配置文件"""
    try:
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        
        print(f"[KUBECONFIG] Generate kubeconfig requested for cluster {cluster} by user {username}")
        
        configs = load_all_configs()
        if cluster not in configs:
            error_msg = f"找不到集群 {cluster}"
            print(f"[KUBECONFIG] Error: {error_msg}")
            print(f"[KUBECONFIG] Available configs: {list(configs.keys())}")
            raise HTTPException(status_code=404, detail={"message": error_msg})
            
        kubeconfig_path = configs[cluster]
        print(f"[KUBECONFIG] Using kubeconfig path: {kubeconfig_path}")
        
        # 获取将要生成的配置文件路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        print(f"[KUBECONFIG] User config path: {user_config_path}")
        
        # 确保用户目录存在
        user_config_dir = os.path.dirname(user_config_path)
        os.makedirs(user_config_dir, exist_ok=True)
        print(f"[KUBECONFIG] Ensured user directory exists: {user_config_dir}")
        
        try:
            # 直接从文件读取原始配置
            print(f"[KUBECONFIG] Reading original kubeconfig from: {kubeconfig_path}")
            with open(kubeconfig_path) as f:
                kube_config = yaml.safe_load(f)
                print(f"[KUBECONFIG] Successfully loaded original kubeconfig content")
            
            if not isinstance(kube_config, dict):
                error_msg = "Invalid kubeconfig format: not a dictionary"
                print(f"[KUBECONFIG] Error: {error_msg}")
                raise HTTPException(status_code=500, detail={"message": error_msg})
            
            # 获取集群信息
            cluster_info = None
            for c in kube_config.get('clusters', []):
                if c['name'] == kube_config.get('current-context'):
                    cluster_info = c
                    print(f"[KUBECONFIG] Found cluster info for: {c['name']}")
                    break
                
            if not cluster_info:
                # 尝试从第一个集群获取信息
                if kube_config.get('clusters'):
                    cluster_info = kube_config['clusters'][0]
                    print(f"[KUBECONFIG] Using first available cluster: {cluster_info['name']}")
                else:
                    error_msg = "No cluster information found in kubeconfig"
                    print(f"[KUBECONFIG] Error: {error_msg}")
                    raise HTTPException(status_code=500, detail={"message": error_msg})
            
            # 设置 KUBECONFIG 环境变量
            os.environ['KUBECONFIG'] = kubeconfig_path
            
            # 获取 ServiceAccount token
            v1 = client.CoreV1Api()
            print(f"[KUBECONFIG] Looking for ServiceAccount: {username}")
            
            try:
                # 尝试获取 ServiceAccount
                sa = v1.read_namespaced_service_account(username, "default")
                print(f"[KUBECONFIG] Found ServiceAccount: {username}")
                
                # 获取 ServiceAccount 的 ClusterRoleBindings
                rbac = client.RbacAuthorizationV1Api()
                bindings = rbac.list_cluster_role_binding()
                has_node_permission = False
                
                # 检查是否有权限访问节点
                for binding in bindings.items:
                    for subject in binding.subjects or []:
                        if (subject.kind == "ServiceAccount" and 
                            subject.name == username and 
                            subject.namespace == "default"):
                            try:
                                role = rbac.read_cluster_role(binding.role_ref.name)
                                for rule in role.rules:
                                    if ("" in rule.api_groups or "core" in rule.api_groups) and \
                                       ("nodes" in rule.resources) and \
                                       ("list" in rule.verbs or "*" in rule.verbs):
                                        has_node_permission = True
                                        break
                            except Exception as e:
                                print(f"[KUBECONFIG] Error checking role {binding.role_ref.name}: {e}")
                
                if not has_node_permission:
                    print(f"[KUBECONFIG] Warning: User {username} does not have permission to list nodes")
                
            except client.rest.ApiException as e:
                error_msg = f"无法找到用户 {username} 的 ServiceAccount: {e.status} {e.reason}"
                print(f"[KUBECONFIG] Error: {error_msg}")
                print(f"[KUBECONFIG] API Exception: {e}")
                raise HTTPException(status_code=500, detail={"message": error_msg})
            
            # 获取 ServiceAccount 的 token
            try:
                print(f"[KUBECONFIG] Looking for ServiceAccount token")
                sa_secrets = v1.list_namespaced_secret(
                    "default",
                    field_selector=f"type=kubernetes.io/service-account-token"
                )
                
                if not sa_secrets or not sa_secrets.items:
                    error_msg = f"找不到任何 ServiceAccount token"
                    print(f"[KUBECONFIG] Error: {error_msg}")
                    raise HTTPException(status_code=500, detail={"message": error_msg})
                
                sa_token = None
                # 列出所有找到的 ServiceAccount
                for secret in sa_secrets.items:
                    sa_name = secret.metadata.annotations.get('kubernetes.io/service-account.name')
                    print(f"[KUBECONFIG] Found token for ServiceAccount: {sa_name}")
                    if sa_name == username:
                        sa_token = base64.b64decode(secret.data['token']).decode('utf-8')
                        print(f"[KUBECONFIG] Found token for target ServiceAccount: {username}")
                        break
                
                if not sa_token:
                    error_msg = f"找不到用户 {username} 的 ServiceAccount 令牌"
                    print(f"[KUBECONFIG] Error: {error_msg}")
                    print(f"[KUBECONFIG] Available ServiceAccounts with tokens: {[secret.metadata.annotations.get('kubernetes.io/service-account.name') for secret in sa_secrets.items if secret.metadata.annotations.get('kubernetes.io/service-account.name')]}")
                    raise HTTPException(status_code=500, detail={"message": error_msg})
                
                # 使用 ServiceAccount token 创建新的配置
                new_config = {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "current-context": cluster,
                    "clusters": [{
                        "name": cluster,
                        "cluster": {
                            "server": cluster_info['cluster']['server'],
                            "certificate-authority-data": cluster_info['cluster'].get('certificate-authority-data', ''),
                            "insecure-skip-tls-verify": cluster_info['cluster'].get('insecure-skip-tls-verify', False)
                        }
                    }],
                    "contexts": [{
                        "name": cluster,
                        "context": {
                            "cluster": cluster,
                            "user": username,
                            "namespace": "default"
                        }
                    }],
                    "users": [{
                        "name": username,
                        "user": {
                            "token": sa_token
                        }
                    }]
                }
                
                # 写入配置
                print(f"[KUBECONFIG] Writing config to: {user_config_path}")
                try:
                    with open(user_config_path, 'w') as f:
                        yaml.safe_dump(new_config, f)
                        f.flush()
                        os.fsync(f.fileno())
                    print(f"[KUBECONFIG] Successfully wrote config to file")
                except Exception as e:
                    error_msg = f"写入配置文件时出错: {str(e)}"
                    print(f"[KUBECONFIG] Error: {error_msg}")
                    print(f"[KUBECONFIG] Exception: {e}")
                    raise HTTPException(status_code=500, detail={"message": error_msg})
                
                # 验证文件是否存在
                if os.path.exists(user_config_path):
                    file_size = os.path.getsize(user_config_path)
                    print(f"[KUBECONFIG] Verified generated kubeconfig exists with size: {file_size} bytes")
                    
                    # 验证文件内容
                    try:
                        with open(user_config_path) as f:
                            test_config = yaml.safe_load(f)
                        print(f"[KUBECONFIG] Successfully validated config file format")
                        
                        # 验证访问权限
                        try:
                            print(f"[KUBECONFIG] Testing cluster access with generated config")
                            config.load_kube_config(user_config_path)
                            test_v1 = client.CoreV1Api()
                            # 尝试列出命名空间而不是节点，因为这个权限更常见
                            test_v1.list_namespace(_request_timeout=5)
                            print(f"[KUBECONFIG] Successfully validated cluster access")
                            
                            if not has_node_permission:
                                return {
                                    "message": "Successfully generated kubeconfig",
                                    "status": "success",
                                    "warning": "User does not have permission to list nodes"
                                }
                            
                            return {"message": "Successfully generated kubeconfig", "status": "success"}
                        except Exception as e:
                            print(f"[KUBECONFIG] Warning: Cluster access test failed: {e}")
                            return {
                                "message": "Generated kubeconfig but access test failed",
                                "status": "warning",
                                "error": str(e)
                            }
                        
                    except Exception as e:
                        error_msg = f"生成配置后验证失败: {str(e)}"
                        print(f"[KUBECONFIG] Error: {error_msg}")
                        print(f"[KUBECONFIG] Exception: {e}")
                        raise HTTPException(status_code=500, detail={"message": error_msg})
                else:
                    error_msg = "生成配置文件后找不到该文件"
                    print(f"[KUBECONFIG] Error: {error_msg}")
                    raise HTTPException(status_code=500, detail={"message": error_msg})
                    
            except HTTPException:
                raise
            except Exception as e:
                error_msg = f"获取 ServiceAccount token 时出错: {str(e)}"
                print(f"[KUBECONFIG] Error: {error_msg}")
                print(f"[KUBECONFIG] Exception: {e}")
                raise HTTPException(status_code=500, detail={"message": error_msg})
                
        except HTTPException:
            raise
        except Exception as e:
            error_msg = f"生成 kubeconfig 失败: {str(e)}"
            print(f"[KUBECONFIG] Error: {error_msg}")
            print(f"[KUBECONFIG] Exception: {e}")
            raise HTTPException(status_code=500, detail={"message": error_msg})
            
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"生成 kubeconfig 时出现意外错误: {str(e)}"
        print(f"[KUBECONFIG] Unexpected error: {error_msg}")
        print(f"[KUBECONFIG] Exception: {e}")
        raise HTTPException(status_code=500, detail={"message": error_msg})

@app.get("/api/pods/{cluster}/{namespace}/{pod}/logs")
async def get_pod_logs(
    cluster: str,
    namespace: str,
    pod: str,
    container: str = None,
    token: str = Depends(oauth2_scheme)
):
    try:
        print(f"\n[LOGS] ========== Getting logs for pod {pod} in namespace {namespace} ==========")
        
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        print(f"[LOGS] User: {username}")

        # 获取用户的 kubeconfig 路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        print(f"[LOGS] User kubeconfig path: {user_config_path}")
        
        if not os.path.exists(user_config_path):
            print(f"[LOGS] Error: Kubeconfig not found")
            raise HTTPException(
                status_code=404,
                detail={"message": "未找到用户的 kubeconfig 配置文件，请先生成配置"}
            )

        # 使用用户的 kubeconfig
        config.load_kube_config(user_config_path)
        core_v1 = client.CoreV1Api()
        
        try:
            # 首先获取 Pod 信息以检查容器
            pod_info = core_v1.read_namespaced_pod(pod, namespace)
            
            # 如果没有指定容器且 Pod 有多个容器，返回错误
            if not container:
                containers = [c.name for c in pod_info.spec.containers]
                if len(containers) > 1:
                    print(f"[LOGS] Multiple containers found: {containers}")
                    return {
                        "error": "Pod has multiple containers",
                        "containers": containers
                    }
                container = containers[0]
                print(f"[LOGS] Using default container: {container}")
            
            print(f"[LOGS] Fetching logs for container: {container}")
            logs = core_v1.read_namespaced_pod_log(
                name=pod,
                namespace=namespace,
                container=container,
                tail_lines=1000
            )
            print(f"[LOGS] Successfully fetched logs")
            return {"logs": logs}
            
        except client.rest.ApiException as e:
            print(f"[LOGS] API error: {e}")
            if e.status == 404:
                raise HTTPException(
                    status_code=404,
                    detail={"message": f"未找到指定的 Pod 或容器"}
                )
            elif e.status == 403:
                raise HTTPException(
                    status_code=403,
                    detail={"message": "没有权限查看日志"}
                )
            raise HTTPException(
                status_code=e.status,
                detail={"message": f"获取日志失败: {e.reason}"}
            )
    except HTTPException as he:
        raise he
    except Exception as e:
        print(f"[LOGS] Unexpected error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"message": f"获取 Pod 日志失败: {str(e)}"}
        )
    finally:
        print(f"[LOGS] ========== Finished getting logs for pod {pod} ==========\n")

@app.get("/api/pods/{cluster}/{namespace}/{pod}/exec")
async def exec_pod(
    cluster: str,
    namespace: str,
    pod: str,
    command: str,
    token: str = Depends(oauth2_scheme)
):
    try:
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")

        # 获取用户的 kubeconfig 路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        if not os.path.exists(user_config_path):
            raise HTTPException(
                status_code=404,
                detail={"message": "未找到用户的 kubeconfig 配置文件，请先生成配置"}
            )

        # 使用用户的 kubeconfig
        config.load_kube_config(user_config_path)
        core_v1 = client.CoreV1Api()
        
        exec_command = ['/bin/sh', '-c', command]
        resp = stream.stream(
            core_v1.connect_get_namespaced_pod_exec,
            pod,
            namespace,
            command=exec_command,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False
        )
        return {"output": resp}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": f"执行 Pod 命令失败: {str(e)}"}
        )

def parse_tls_certificate(cert_data: str) -> dict:
    """Parse TLS certificate and extract expiration information"""
    try:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
        expiration = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        now = datetime.utcnow()
        days_until_expiry = (expiration - now).days
        return {
            "expiration": expiration.isoformat(),
            "days_until_expiry": days_until_expiry,
            "is_expired": days_until_expiry < 0
        }
    except Exception as e:
        print(f"Error parsing certificate: {e}")
        return None

@app.get("/api/kubeconfig/{cluster}/status")
async def check_kubeconfig_status(cluster: str, token: str = Depends(oauth2_scheme)):
    """检查用户的 kubeconfig 配置文件状态"""
    try:
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        
        print(f"[KUBECONFIG] Checking kubeconfig status for cluster {cluster} and user {username}")
        
        configs = load_all_configs()
        if cluster not in configs:
            raise HTTPException(status_code=404, detail="Cluster not found")
            
        # 获取用户 kubeconfig 文件路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        exists = os.path.exists(user_config_path)
        
        print(f"[KUBECONFIG] Status for {cluster}: {'exists' if exists else 'not found'}")
        
        return {
            "exists": exists,
            "cluster": cluster,
            "username": username
        }
            
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Failed to check kubeconfig status",
                "error": str(e)
            }
        )

@app.get("/api/user/permissions/{cluster}")
async def get_user_permissions(cluster: str, token: str = Depends(oauth2_scheme)):
    """获取用户在指定集群中的权限信息"""
    try:
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        
        # 获取用户的 kubeconfig 路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        if not os.path.exists(user_config_path):
            return {
                "username": username,
                "serviceAccount": username,
                "clusterRoles": [],
                "roles": [],
                "commonPermissions": {
                    "canViewPods": False,
                    "canExecPods": False,
                    "canViewLogs": False,
                    "canViewSecrets": False,
                    "canCreateDeployments": False
                }
            }
        
        # 使用用户的 kubeconfig
        config.load_kube_config(user_config_path)
        rbac_v1 = client.RbacAuthorizationV1Api()
        core_v1 = client.CoreV1Api()
        
        # 获取用户的 ServiceAccount
        try:
            sa = core_v1.read_namespaced_service_account(username, "default")
        except client.rest.ApiException as e:
            raise HTTPException(
                status_code=404,
                detail={"message": f"未找到用户的 ServiceAccount: {str(e)}"}
            )
        
        # 获取所有 ClusterRoleBinding
        bindings = rbac_v1.list_cluster_role_binding()
        user_cluster_roles = []
        
        # 查找与用户关联的 ClusterRoleBinding
        for binding in bindings.items:
            for subject in binding.subjects or []:
                if (subject.kind == "ServiceAccount" and 
                    subject.name == username and 
                    subject.namespace == "default"):
                    # 获取对应的 ClusterRole
                    try:
                        role = rbac_v1.read_cluster_role(binding.role_ref.name)
                        rules = []
                        for rule in role.rules:
                            rules.append({
                                "apiGroups": rule.api_groups,
                                "resources": rule.resources,
                                "verbs": rule.verbs,
                                "resourceNames": rule.resource_names
                            })
                        user_cluster_roles.append({
                            "name": role.metadata.name,
                            "rules": rules
                        })
                    except client.rest.ApiException as e:
                        print(f"Error getting ClusterRole {binding.role_ref.name}: {e}")
        
        # 整理权限信息
        permissions = {
            "username": username,
            "serviceAccount": sa.metadata.name,
            "clusterRoles": user_cluster_roles,
            "commonPermissions": {
                "canViewPods": any(
                    "pods" in rule.get("resources", []) and "list" in rule.get("verbs", [])
                    for role in user_cluster_roles
                    for rule in role["rules"]
                ),
                "canExecPods": any(
                    "pods/exec" in rule.get("resources", []) and "create" in rule.get("verbs", [])
                    for role in user_cluster_roles
                    for rule in role["rules"]
                ),
                "canViewLogs": any(
                    "pods/log" in rule.get("resources", []) and "get" in rule.get("verbs", [])
                    for role in user_cluster_roles
                    for rule in role["rules"]
                ),
                "canViewSecrets": any(
                    "secrets" in rule.get("resources", []) and "list" in rule.get("verbs", [])
                    for role in user_cluster_roles
                    for rule in role["rules"]
                ),
                "canCreateDeployments": any(
                    "deployments" in rule.get("resources", []) and "create" in rule.get("verbs", [])
                    for role in user_cluster_roles
                    for rule in role["rules"]
                )
            }
        }
        
        return permissions
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": f"获取用户权限信息失败: {str(e)}"}
        )

@app.get("/api/kubeconfig/{cluster}/validate")
async def validate_kubeconfig(cluster: str, token: str = Depends(oauth2_scheme)):
    """验证用户的 kubeconfig 是否有效"""
    try:
        print(f"\n[VALIDATE] ========== Validating kubeconfig for cluster: {cluster} ==========")
        
        # 获取当前用户信息
        user = get_current_user(token)
        username = user.get("sub")
        print(f"[VALIDATE] User: {username}")
        
        # 获取用户的 kubeconfig 路径
        user_config_path = get_user_kubeconfig_path(username, cluster)
        print(f"[VALIDATE] User kubeconfig path: {user_config_path}")
        
        # 检查文件是否存在
        if not os.path.exists(user_config_path):
            print(f"[VALIDATE] Error: Kubeconfig not found at {user_config_path}")
            return {"valid": False, "message": "kubeconfig 文件不存在"}
            
        # 检查文件是否为空
        if os.path.getsize(user_config_path) == 0:
            print(f"[VALIDATE] Error: Kubeconfig is empty")
            return {"valid": False, "message": "kubeconfig 文件为空"}
            
        try:
            print(f"[VALIDATE] Reading kubeconfig content")
            with open(user_config_path) as f:
                config_content = yaml.safe_load(f)
                
            # 验证配置文件格式
            if not isinstance(config_content, dict):
                print(f"[VALIDATE] Error: Invalid kubeconfig format")
                return {"valid": False, "message": "kubeconfig 格式无效"}
                
            required_fields = ['apiVersion', 'kind', 'clusters', 'contexts', 'current-context', 'users']
            missing_fields = [field for field in required_fields if field not in config_content]
            if missing_fields:
                print(f"[VALIDATE] Error: Missing required fields: {missing_fields}")
                return {"valid": False, "message": f"kubeconfig 缺少必要字段: {', '.join(missing_fields)}"}
            
            print(f"[VALIDATE] Loading kubeconfig")
            # 尝试加载 kubeconfig
            config.load_kube_config(user_config_path)
            
            print(f"[VALIDATE] Creating test client")
            # 尝试创建客户端并进行简单的 API 调用
            v1 = client.CoreV1Api()
            
            print(f"[VALIDATE] Testing API connection")
            # 测试连接，设置较短的超时时间
            v1.list_namespace(_request_timeout=5)
            
            print(f"[VALIDATE] Successfully validated kubeconfig")
            print(f"[VALIDATE] ========== Finished validation for cluster: {cluster} ==========\n")
            return {"valid": True}
            
        except yaml.YAMLError as e:
            print(f"[VALIDATE] Error parsing YAML: {e}")
            return {"valid": False, "message": f"kubeconfig YAML 格式错误: {str(e)}"}
        except config.config_exception.ConfigException as e:
            print(f"[VALIDATE] Error loading kubeconfig: {e}")
            return {"valid": False, "message": f"加载 kubeconfig 失败: {str(e)}"}
        except client.rest.ApiException as e:
            print(f"[VALIDATE] API error: {e}")
            v1.list_namespace(_request_timeout=5)  # 设置超时时间为 5 秒
            return {"valid": True}
        except Exception as e:
            print(f"验证 kubeconfig 失败: {str(e)}")
            return {"valid": False, "message": "kubeconfig 验证失败"}
            
    except Exception as e:
        print(f"验证 kubeconfig 时发生错误: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={"message": f"验证 kubeconfig 失败: {str(e)}"}
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 