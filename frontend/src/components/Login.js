import React from 'react';
import { 
  Layout,
  Form,
  Input,
  Button,
  Typography,
  Card,
  Space,
  Collapse,
  message
} from 'antd';
import {
  UserOutlined,
  LockOutlined,
  QuestionCircleOutlined
} from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;
const { Panel } = Collapse;

const Login = ({ onLogin }) => {
  const [form] = Form.useForm();

  const handleSubmit = async (values) => {
    try {
      await onLogin(values.username, values.password);
    } catch (error) {
      console.error('Login form error:', error);
      message.error('登录失败: ' + (error.message || '未知错误'));
    }
  };

  const secretTemplate = `# 为每个用户创建单独的 Secret
# user1 的凭据
apiVersion: v1
kind: Secret
metadata:
  name: user-credentials-user1  # 根据用户名命名
  namespace: default
  labels:
    app: k8s-resource-panel
    type: user-credentials
type: Opaque
data:
  username: dXNlcjE=  # 'user1' 的 base64 编码
  password: cGFzc3dvcmQx  # 'password1' 的 base64 编码
---
# user2 的凭据
apiVersion: v1
kind: Secret
metadata:
  name: user-credentials-user2  # 根据用户名命名
  namespace: default
  labels:
    app: k8s-resource-panel
    type: user-credentials
type: Opaque
data:
  username: dXNlcjI=  # 'user2' 的 base64 编码
  password: cGFzc3dvcmQy  # 'password2' 的 base64 编码`;

  const rbacTemplate = `# 为每个用户创建单独的 ServiceAccount 和 RoleBinding
# user1 的 RBAC 配置
apiVersion: v1
kind: ServiceAccount
metadata:
  name: user1-sa                                     
  namespace: default                                
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: resource-viewer-role  # 共享的 ClusterRole
rules:
- apiGroups: [""]
  resources: ["nodes","services","namespaces","configmaps","endpoints","events","serviceaccounts"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles","clusterrolebindings"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs","cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.istio.io"]
  resources: ["gateways","virtualservices"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets","daemonsets", "statefulsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/exec","pods"]
  verbs: ["get", "list", "watch", "delete", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: user1-rolebinding
subjects:
- name: user1-sa
  kind: ServiceAccount
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  name: resource-viewer-role
  kind: ClusterRole
---
# user2 的 RBAC 配置
apiVersion: v1
kind: ServiceAccount
metadata:
  name: user2-sa                                     
  namespace: default                                
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: user2-rolebinding
subjects:
- name: user2-sa
  kind: ServiceAccount
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  name: resource-viewer-role
  kind: ClusterRole`;

  return (
    <Layout style={{ minHeight: '100vh', display: 'flex', justifyContent: 'center', alignItems: 'center', background: '#f0f2f5' }}>
      <Card style={{ width: 400, padding: '24px' }}>
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <Title level={2} style={{ textAlign: 'center', marginBottom: 32 }}>
            Kubernetes Resource Panel
          </Title>

          <Form
            form={form}
            onFinish={handleSubmit}
            layout="vertical"
          >
            <Form.Item
              name="username"
              rules={[{ required: true, message: '请输入用户名' }]}
            >
              <Input 
                prefix={<UserOutlined />} 
                placeholder="用户名"
                size="large"
              />
            </Form.Item>

            <Form.Item
              name="password"
              rules={[{ required: true, message: '请输入密码' }]}
            >
              <Input.Password
                prefix={<LockOutlined />}
                placeholder="密码"
                size="large"
              />
            </Form.Item>

            <Form.Item>
              <Button type="primary" htmlType="submit" block size="large">
                登录
              </Button>
            </Form.Item>
          </Form>

          <Collapse ghost>
            <Panel 
              header={
                <Space>
                  <QuestionCircleOutlined />
                  <Text>Need help setting up your account?</Text>
                </Space>
              }
              key="1"
            >
              <Space direction="vertical" style={{ width: '100%' }}>
                <Paragraph>
                  To set up user accounts, you need to create the following resources in your Kubernetes cluster:
                </Paragraph>

                <Collapse>
                  <Panel header="1. Create Secrets for User Credentials" key="1">
                    <pre style={{ background: '#f6f8fa', padding: 16, borderRadius: 4, overflow: 'auto' }}>
                      {secretTemplate}
                    </pre>
                    <Paragraph>
                      Note: To generate base64 values for credentials, you can use:
                      <pre style={{ background: '#f6f8fa', padding: 16, borderRadius: 4 }}>
                        echo -n 'username' | base64{'\n'}
                        echo -n 'password' | base64
                      </pre>
                      Replace 'username' and 'password' with actual values.
                      For each new user, create a new Secret with a unique name (e.g., user-credentials-{'{username}'}).
                    </Paragraph>
                  </Panel>

                  <Panel header="2. Create RBAC Configuration" key="2">
                    <pre style={{ background: '#f6f8fa', padding: 16, borderRadius: 4, overflow: 'auto' }}>
                      {rbacTemplate}
                    </pre>
                    <Paragraph>
                      Note: For each new user:
                      <ul>
                        <li>Create a new ServiceAccount with a unique name (e.g., {'{username}'}-sa)</li>
                        <li>Create a new ClusterRoleBinding with a unique name (e.g., {'{username}'}-rolebinding)</li>
                        <li>The ClusterRole can be shared among users unless different permissions are needed</li>
                      </ul>
                    </Paragraph>
                  </Panel>
                </Collapse>

                <Paragraph>
                  Apply these configurations to your cluster using kubectl:
                  <pre style={{ background: '#f6f8fa', padding: 16, borderRadius: 4 }}>
                    kubectl apply -f secrets.yaml{'\n'}
                    kubectl apply -f rbac.yaml
                  </pre>
                </Paragraph>
              </Space>
            </Panel>
          </Collapse>
        </Space>
      </Card>
    </Layout>
  );
};

export default Login; 