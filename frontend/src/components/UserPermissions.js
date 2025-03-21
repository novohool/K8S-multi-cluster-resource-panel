import React, { useState, useEffect } from 'react';
import { Card, Typography, List, Tag, Space, Collapse, Spin, Alert } from 'antd';
import { CheckCircleOutlined, CloseCircleOutlined } from '@ant-design/icons';
import { API_BASE_URL } from '../config';

const { Title, Text } = Typography;
const { Panel } = Collapse;

const UserPermissions = ({ cluster, token }) => {
  const [permissions, setPermissions] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchPermissions = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await fetch(`${API_BASE_URL}/api/user/permissions/${cluster}`, {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => null);
          throw new Error(
            errorData?.detail?.message || 
            errorData?.detail || 
            `获取权限信息失败: ${response.statusText}`
          );
        }
        
        const data = await response.json();
        setPermissions(data);
      } catch (err) {
        setError(err.message);
        console.error('获取权限信息失败:', err);
      } finally {
        setLoading(false);
      }
    };

    if (cluster && token) {
      fetchPermissions();
    }
  }, [cluster, token]);

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '24px' }}>
        <Spin size="large" />
      </div>
    );
  }

  if (error) {
    return (
      <Alert
        message="错误"
        description={error}
        type="error"
        style={{ marginTop: '16px' }}
      />
    );
  }

  if (!permissions) {
    return null;
  }

  const { commonPermissions, clusterRoles } = permissions;

  const renderRules = (rules) => (
    <List
      dataSource={rules}
      renderItem={(rule, index) => (
        <List.Item key={index}>
          <div style={{ width: '100%' }}>
            <div style={{ marginBottom: '8px' }}>
              <Text strong>API Groups:</Text>
              <div style={{ marginTop: '4px' }}>
                <Space wrap>
                  {rule.apiGroups?.map((group) => (
                    <Tag key={group}>{group || '*'}</Tag>
                  ))}
                </Space>
              </div>
            </div>
            
            <div style={{ marginBottom: '8px' }}>
              <Text strong>Resources:</Text>
              <div style={{ marginTop: '4px' }}>
                <Space wrap>
                  {rule.resources?.map((resource) => (
                    <Tag key={resource}>{resource}</Tag>
                  ))}
                </Space>
              </div>
            </div>
            
            <div>
              <Text strong>Verbs:</Text>
              <div style={{ marginTop: '4px' }}>
                <Space wrap>
                  {rule.verbs?.map((verb) => (
                    <Tag key={verb} color="blue">{verb}</Tag>
                  ))}
                </Space>
              </div>
            </div>
          </div>
        </List.Item>
      )}
    />
  );

  return (
    <Card style={{ marginTop: '16px' }}>
      <Title level={4}>权限信息</Title>
      
      <div style={{ marginBottom: '24px' }}>
        <Title level={5}>常用权限</Title>
        <List
          size="small"
          dataSource={Object.entries(commonPermissions)}
          renderItem={([key, value]) => (
            <List.Item>
              <Space>
                {value ? (
                  <CheckCircleOutlined style={{ color: '#52c41a' }} />
                ) : (
                  <CloseCircleOutlined style={{ color: '#f5222d' }} />
                )}
                <Text>
                  {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                </Text>
              </Space>
            </List.Item>
          )}
        />
      </div>

      <Title level={5}>集群角色 (ClusterRoles)</Title>
      <Collapse>
        {clusterRoles.map((role) => (
          <Panel header={role.name} key={role.name}>
            {renderRules(role.rules)}
          </Panel>
        ))}
      </Collapse>
    </Card>
  );
};

export default UserPermissions; 