import React from 'react';
import { Select, Button, Space, message } from 'antd';
import { SyncOutlined, DownloadOutlined } from '@ant-design/icons';
import { API_BASE_URL } from '../config';

const ClusterSelector = ({ clusters, selectedCluster, onClusterChange, token }) => {
  const refreshKubeconfig = async () => {
    if (!selectedCluster) {
      message.warning('请先选择一个集群');
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/kubeconfig/${selectedCluster}/refresh`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail?.message || '刷新 kubeconfig 失败');
      }

      message.success('成功刷新 kubeconfig');
    } catch (error) {
      console.error('Error refreshing kubeconfig:', error);
      message.error(error.message || '刷新 kubeconfig 失败');
    }
  };

  const generateKubeconfig = async () => {
    if (!selectedCluster) {
      message.warning('请先选择一个集群');
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/kubeconfig/${selectedCluster}/generate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail?.message || '生成 kubeconfig 失败');
      }

      message.success('成功生成 kubeconfig');
    } catch (error) {
      console.error('Error generating kubeconfig:', error);
      message.error(error.message || '生成 kubeconfig 失败');
    }
  };

  return (
    <Space>
      <Select
        style={{ width: 200 }}
        placeholder="选择集群"
        value={selectedCluster}
        onChange={onClusterChange}
        options={clusters.map(cluster => ({
          value: cluster,
          label: cluster
        }))}
      />
      <Button 
        type="primary" 
        icon={<DownloadOutlined />}
        onClick={generateKubeconfig}
      >
        生成配置
      </Button>
      <Button 
        icon={<SyncOutlined />}
        onClick={refreshKubeconfig}
      >
        刷新配置
      </Button>
    </Space>
  );
};

export default ClusterSelector; 