import React, { useState, useEffect } from 'react';
import { Card, Table, Button, Space, message, Badge, Alert } from 'antd';
import { ReloadOutlined, DownloadOutlined, CheckCircleOutlined } from '@ant-design/icons';
import { API_BASE_URL } from '../config';
import UserPermissions from './UserPermissions';

const UserProfile = ({ token, username, clusters }) => {
  const [kubeconfigStatus, setKubeconfigStatus] = useState({});
  const [kubeconfigValidation, setKubeconfigValidation] = useState({});
  const [loading, setLoading] = useState({});
  const [selectedCluster, setSelectedCluster] = useState('');

  // 检查每个集群的 kubeconfig 状态
  const checkKubeconfigStatus = async (cluster) => {
    try {
      console.log(`[STATUS] Checking kubeconfig status for cluster ${cluster}`);
      const response = await fetch(`${API_BASE_URL}/api/kubeconfig/${cluster}/status`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail?.message || '检查状态失败');
      }
      
      const data = await response.json();
      console.log(`[STATUS] Status result:`, data);
      
      setKubeconfigStatus(prev => ({
        ...prev,
        [cluster]: data.exists
      }));
      
      // 如果 kubeconfig 存在，验证其有效性
      if (data.exists) {
        // 等待一段时间后再验证配置
        setTimeout(async () => {
          await validateKubeconfig(cluster);
        }, 1000);
      }
    } catch (error) {
      console.error(`[STATUS] Error checking status for ${cluster}:`, error);
      setKubeconfigStatus(prev => ({
        ...prev,
        [cluster]: false
      }));
    }
  };

  // 验证 kubeconfig 的有效性
  const validateKubeconfig = async (cluster) => {
    try {
      console.log(`[VALIDATE] Validating kubeconfig for cluster ${cluster}`);
      const response = await fetch(`${API_BASE_URL}/api/kubeconfig/${cluster}/validate`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (!response.ok) {
        throw new Error('验证请求失败');
      }
      
      const data = await response.json();
      console.log(`[VALIDATE] Validation result:`, data);
      
      setKubeconfigValidation(prev => ({
        ...prev,
        [cluster]: data.valid
      }));
      
      if (!data.valid) {
        message.warning(`集群 ${cluster} 的配置无效: ${data.message}`);
      }
      
      return data.valid;
    } catch (error) {
      console.error(`[VALIDATE] Error validating kubeconfig for ${cluster}:`, error);
      setKubeconfigValidation(prev => ({
        ...prev,
        [cluster]: false
      }));
      return false;
    }
  };

  // 生成指定集群的 kubeconfig
  const generateKubeconfig = async (cluster) => {
    setLoading(prev => ({ ...prev, [cluster]: true }));
    try {
      const response = await fetch(`${API_BASE_URL}/api/kubeconfig/${cluster}/generate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      let responseData;
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        responseData = await response.json();
      } else {
        const text = await response.text();
        throw new Error(`服务器返回非JSON数据: ${text.substring(0, 100)}...`);
      }

      if (!response.ok) {
        throw new Error(
          responseData.detail?.message || 
          (typeof responseData.detail === 'string' ? responseData.detail : '生成 kubeconfig 失败')
        );
      }
      
      message.success(`${cluster} 集群的 kubeconfig 生成成功`);
      await checkKubeconfigStatus(cluster);
      setSelectedCluster(cluster);
    } catch (error) {
      console.error('generateKubeconfig error:', error);
      message.error({
        content: `生成 kubeconfig 失败: ${error.message}`,
        duration: 10,
      });
    } finally {
      setLoading(prev => ({ ...prev, [cluster]: false }));
    }
  };

  // 刷新指定集群的 kubeconfig
  const refreshKubeconfig = async (cluster) => {
    setLoading(prev => ({ ...prev, [cluster]: true }));
    try {
      const response = await fetch(`${API_BASE_URL}/api/kubeconfig/${cluster}/refresh`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      let responseData;
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        responseData = await response.json();
      } else {
        const text = await response.text();
        throw new Error(`服务器返回非JSON数据: ${text.substring(0, 100)}...`);
      }

      if (!response.ok) {
        throw new Error(
          responseData.detail?.message || 
          (typeof responseData.detail === 'string' ? responseData.detail : '刷新 kubeconfig 失败')
        );
      }
      
      message.success(`${cluster} 集群的 kubeconfig 刷新成功`);
      await checkKubeconfigStatus(cluster);
      
      // 等待一段时间后再验证配置
      setTimeout(async () => {
        try {
          await validateKubeconfig(cluster);
        } catch (error) {
          console.error('验证配置失败:', error);
        }
      }, 2000);
      
    } catch (error) {
      console.error(`刷新 kubeconfig 失败:`, error);
      message.error(`刷新 kubeconfig 失败: ${error.message}`);
    } finally {
      setLoading(prev => ({ ...prev, [cluster]: false }));
    }
  };

  useEffect(() => {
    if (clusters && clusters.length > 0) {
      clusters.forEach(cluster => {
        checkKubeconfigStatus(cluster);
      });
      setSelectedCluster(clusters[0]);
    }
  }, [clusters]);

  const getStatusBadge = (cluster) => {
    if (!kubeconfigStatus[cluster]) {
      return <Badge status="default" text="未配置" />;
    }
    if (!kubeconfigValidation[cluster]) {
      return (
        <Space>
          <Badge status="warning" text="配置无效" />
          <Button
            type="link"
            size="small"
            onClick={(e) => {
              e.stopPropagation();
              refreshKubeconfig(cluster);
            }}
          >
            重新验证
          </Button>
        </Space>
      );
    }
    return <Badge status="success" text="配置有效" />;
  };

  const columns = [
    {
      title: '集群名称',
      dataIndex: 'name',
      key: 'name',
      render: (name) => (
        <Button 
          type="link" 
          onClick={() => setSelectedCluster(name)}
          style={{ 
            color: selectedCluster === name ? '#1890ff' : 'inherit',
            fontWeight: selectedCluster === name ? 'bold' : 'normal'
          }}
        >
          {name}
        </Button>
      )
    },
    {
      title: '配置状态',
      key: 'status',
      render: (_, record) => getStatusBadge(record.name)
    },
    {
      title: '操作',
      key: 'action',
      render: (_, record) => (
        <Space>
          {!kubeconfigStatus[record.name] ? (
            <Button
              type="primary"
              icon={<DownloadOutlined />}
              loading={loading[record.name]}
              onClick={() => generateKubeconfig(record.name)}
            >
              生成配置
            </Button>
          ) : (
            <Button
              icon={<ReloadOutlined />}
              loading={loading[record.name]}
              onClick={() => refreshKubeconfig(record.name)}
            >
              刷新配置
            </Button>
          )}
        </Space>
      )
    }
  ];

  return (
    <Card title={`用户信息 - ${username}`}>
      <Table
        columns={columns}
        dataSource={clusters.map(cluster => ({ name: cluster }))}
        rowKey="name"
        pagination={false}
        onRow={(record) => ({
          onClick: () => setSelectedCluster(record.name),
          style: {
            cursor: 'pointer',
            backgroundColor: selectedCluster === record.name ? '#f0f5ff' : 'inherit'
          }
        })}
      />
      
      {selectedCluster && !kubeconfigStatus[selectedCluster] && (
        <Alert
          style={{ marginTop: '16px' }}
          message="未配置集群访问"
          description="请先生成集群配置文件以查看权限信息"
          type="info"
          showIcon
        />
      )}
      
      {selectedCluster && kubeconfigStatus[selectedCluster] && !kubeconfigValidation[selectedCluster] && (
        <Alert
          style={{ marginTop: '16px' }}
          message="配置验证失败"
          description="集群配置文件无效，请尝试刷新配置"
          type="warning"
          showIcon
        />
      )}
      
      {selectedCluster && kubeconfigStatus[selectedCluster] && kubeconfigValidation[selectedCluster] && (
        <UserPermissions cluster={selectedCluster} token={token} />
      )}
    </Card>
  );
};

export default UserProfile; 