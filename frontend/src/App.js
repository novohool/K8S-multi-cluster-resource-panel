import React, { useState, useEffect, useCallback } from 'react';
import { 
  Layout, 
  Table, 
  Row, 
  Col, 
  Select, 
  Typography, 
  Spin, 
  message, 
  Collapse, 
  Input, 
  Space,
  Drawer,
  Button,
  Menu,
  Tag,
  Tooltip,
  Badge
} from 'antd';
import { 
  CloudServerOutlined, 
  ContainerOutlined,
  DeploymentUnitOutlined,
  ApiOutlined,
  GlobalOutlined,
  ScheduleOutlined,
  GatewayOutlined,
  SearchOutlined,
  MenuOutlined,
  ReloadOutlined,
  SettingOutlined,
  DashboardOutlined,
  FilterOutlined
} from '@ant-design/icons';
import axios from 'axios';

const { Header, Content, Sider } = Layout;
const { Title, Text } = Typography;
const { Option } = Select;
const { Panel } = Collapse;
const { Search } = Input;

const API_BASE_URL = 'http://localhost:8000/api';

function App() {
  const [clusters, setClusters] = useState([]);
  const [selectedCluster, setSelectedCluster] = useState(null);
  const [resources, setResources] = useState({});
  const [loadingResources, setLoadingResources] = useState({});
  const [activeKeys, setActiveKeys] = useState([]);
  const [searchText, setSearchText] = useState({});
  const [globalSearchText, setGlobalSearchText] = useState('');
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedResourceTypes, setSelectedResourceTypes] = useState([]);
  const [collapsed, setCollapsed] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(null);

  useEffect(() => {
    fetchClusters();
  }, []);

  useEffect(() => {
    if (selectedCluster) {
      // 切换集群时清空资源数据
      setResources({});
      setActiveKeys([]);
    }
  }, [selectedCluster]);

  const fetchClusters = async () => {
    try {
      console.log('Fetching clusters...');
      const response = await axios.get(`${API_BASE_URL}/clusters`);
      console.log('Received clusters:', response.data);
      setClusters(response.data.clusters);
      if (response.data.clusters && response.data.clusters.length > 0) {
        console.log('Setting initial cluster:', response.data.clusters[0]);
        setSelectedCluster(response.data.clusters[0]);
      } else {
        console.log('No clusters available');
        message.warning('No Kubernetes clusters found');
      }
    } catch (error) {
      console.error('Error fetching clusters:', error);
      message.error(`Failed to fetch clusters: ${error.message}`);
    }
  };

  useEffect(() => {
    if (refreshInterval && selectedCluster) {
      const timer = setInterval(() => {
        activeKeys.forEach(key => {
          fetchResourceType(selectedCluster, key, true);
        });
      }, refreshInterval * 1000);
      return () => clearInterval(timer);
    }
  }, [refreshInterval, selectedCluster, activeKeys]);

  const fetchResourceType = async (cluster, resourceType, silent = false) => {
    if (!cluster || (!silent && resources[resourceType])) return;

    setLoadingResources(prev => ({ ...prev, [resourceType]: !silent }));
    try {
      const response = await axios.get(`${API_BASE_URL}/resources/${cluster}/${resourceType}`);
      setResources(prev => ({
        ...prev,
        [resourceType]: response.data || []
      }));
      if (!silent) {
        message.success(`${resourceType} 加载成功`);
      }
    } catch (error) {
      console.error(`Error fetching ${resourceType}:`, error);
      if (!silent) {
        message.error(`Failed to fetch ${resourceType}: ${error.message}`);
      }
      setResources(prev => ({ ...prev, [resourceType]: [] }));
    } finally {
      setLoadingResources(prev => ({ ...prev, [resourceType]: false }));
    }
  };

  const handleMenuClick = (resourceType) => {
    const newKeys = activeKeys.includes(resourceType)
      ? activeKeys.filter(key => key !== resourceType)
      : [...activeKeys, resourceType];
    setActiveKeys(newKeys);
    if (!activeKeys.includes(resourceType)) {
      fetchResourceType(selectedCluster, resourceType);
    }
  };

  const getResourceCount = (resourceType) => {
    return resources[resourceType]?.length || 0;
  };

  const handleRefresh = () => {
    if (selectedCluster) {
      activeKeys.forEach(key => {
        fetchResourceType(selectedCluster, key, true);
      });
      message.success('正在刷新资源...');
    }
  };

  const handleSearch = (selectedKeys, confirm, dataIndex) => {
    confirm();
    setSearchText({
      ...searchText,
      [dataIndex]: selectedKeys[0]
    });
  };

  const handleReset = (clearFilters, dataIndex) => {
    clearFilters();
    setSearchText({
      ...searchText,
      [dataIndex]: ''
    });
  };

  const handleGlobalSearch = (value) => {
    setGlobalSearchText(value);
  };

  const getColumnSearchProps = useCallback((dataIndex, placeholder) => ({
    filterDropdown: ({ setSelectedKeys, selectedKeys, confirm, clearFilters }) => (
      <div style={{ padding: 8 }}>
        <Input
          placeholder={`搜索 ${placeholder}`}
          value={selectedKeys[0]}
          onChange={e => setSelectedKeys(e.target.value ? [e.target.value] : [])}
          onPressEnter={() => handleSearch(selectedKeys, confirm, dataIndex)}
          style={{ width: 188, marginBottom: 8, display: 'block' }}
        />
        <Space>
          <button
            type="button"
            onClick={() => handleSearch(selectedKeys, confirm, dataIndex)}
            style={{ width: 90 }}
          >
            搜索
          </button>
          <button
            type="button"
            onClick={() => handleReset(clearFilters, dataIndex)}
            style={{ width: 90 }}
          >
            重置
          </button>
        </Space>
      </div>
    ),
    filterIcon: filtered => <SearchOutlined style={{ color: filtered ? '#1890ff' : undefined }} />,
    onFilter: (value, record) =>
      record[dataIndex]
        ? record[dataIndex].toString().toLowerCase().includes(value.toLowerCase())
        : '',
    filteredValue: searchText[dataIndex] ? [searchText[dataIndex]] : null,
  }), [searchText]);

  const filterData = useCallback((data, resourceType) => {
    if (!globalSearchText) return data;
    
    const searchColumns = resourceTables[resourceType].columns
      .map(col => col.dataIndex)
      .filter(Boolean);

    return data.filter(record => 
      searchColumns.some(column => {
        const value = record[column];
        if (Array.isArray(value)) {
          return value.join(', ').toLowerCase().includes(globalSearchText.toLowerCase());
        }
        return value && value.toString().toLowerCase().includes(globalSearchText.toLowerCase());
      })
    );
  }, [globalSearchText]);

  const resourceTables = {
    nodes: {
      title: 'Nodes',
      icon: <CloudServerOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', '节点名称'),
          defaultSortOrder: 'ascend',
          sorter: (a, b) => a.name.localeCompare(b.name)
        },
        { 
          title: 'Status', 
          dataIndex: 'status', 
          key: 'status',
          ...getColumnSearchProps('status', '状态')
        },
        { 
          title: 'Version', 
          dataIndex: 'kubelet_version', 
          key: 'version',
          ...getColumnSearchProps('kubelet_version', '版本')
        }
      ]
    },
    pods: {
      title: 'Pods',
      icon: <ContainerOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', 'Pod名称')
        },
        { 
          title: 'Namespace', 
          dataIndex: 'namespace', 
          key: 'namespace',
          ...getColumnSearchProps('namespace', '命名空间')
        },
        { 
          title: 'Status', 
          dataIndex: 'status', 
          key: 'status',
          ...getColumnSearchProps('status', '状态')
        },
        { 
          title: 'Node', 
          dataIndex: 'node', 
          key: 'node',
          ...getColumnSearchProps('node', '节点')
        }
      ]
    },
    deployments: {
      title: 'Deployments',
      icon: <DeploymentUnitOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', '部署名称')
        },
        { 
          title: 'Namespace', 
          dataIndex: 'namespace', 
          key: 'namespace',
          ...getColumnSearchProps('namespace', '命名空间')
        },
        { 
          title: 'Replicas', 
          dataIndex: 'replicas', 
          key: 'replicas',
          ...getColumnSearchProps('replicas', '副本数')
        }
      ]
    },
    services: {
      title: 'Services',
      icon: <ApiOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', '服务名称')
        },
        { 
          title: 'Namespace', 
          dataIndex: 'namespace', 
          key: 'namespace',
          ...getColumnSearchProps('namespace', '命名空间')
        },
        { 
          title: 'Type', 
          dataIndex: 'type', 
          key: 'type',
          ...getColumnSearchProps('type', '类型')
        },
        { 
          title: 'Cluster IP', 
          dataIndex: 'cluster_ip', 
          key: 'cluster_ip',
          ...getColumnSearchProps('cluster_ip', '集群IP')
        }
      ]
    },
    ingresses: {
      title: 'Ingresses',
      icon: <GlobalOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', 'Ingress名称')
        },
        { 
          title: 'Namespace', 
          dataIndex: 'namespace', 
          key: 'namespace',
          ...getColumnSearchProps('namespace', '命名空间')
        },
        { 
          title: 'Hosts', 
          dataIndex: 'hosts', 
          key: 'hosts',
          render: (hosts) => hosts.join(', '),
          ...getColumnSearchProps('hosts', '主机名')
        }
      ]
    },
    gateways: {
      title: 'Istio Gateways',
      icon: <GatewayOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', '网关名称')
        },
        { 
          title: 'Namespace', 
          dataIndex: 'namespace', 
          key: 'namespace',
          ...getColumnSearchProps('namespace', '命名空间')
        },
        { 
          title: 'Servers', 
          dataIndex: 'servers', 
          key: 'servers',
          ...getColumnSearchProps('servers', '服务器数量')
        }
      ]
    },
    virtualservices: {
      title: 'Istio VirtualServices',
      icon: <GlobalOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', '虚拟服务名称')
        },
        { 
          title: 'Namespace', 
          dataIndex: 'namespace', 
          key: 'namespace',
          ...getColumnSearchProps('namespace', '命名空间')
        },
        { 
          title: 'Gateways', 
          dataIndex: 'gateways', 
          key: 'gateways',
          render: (gateways) => gateways.join(', '),
          ...getColumnSearchProps('gateways', '网关')
        },
        { 
          title: 'Hosts', 
          dataIndex: 'hosts', 
          key: 'hosts',
          render: (hosts) => hosts.join(', '),
          ...getColumnSearchProps('hosts', '主机名')
        }
      ]
    },
    jobs: {
      title: 'Jobs',
      icon: <ScheduleOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', '任务名称')
        },
        { 
          title: 'Namespace', 
          dataIndex: 'namespace', 
          key: 'namespace',
          ...getColumnSearchProps('namespace', '命名空间')
        },
        { 
          title: 'Status', 
          dataIndex: 'status', 
          key: 'status',
          ...getColumnSearchProps('status', '状态')
        }
      ]
    },
    cronjobs: {
      title: 'CronJobs',
      icon: <ScheduleOutlined />,
      columns: [
        { 
          title: 'Name', 
          dataIndex: 'name', 
          key: 'name',
          ...getColumnSearchProps('name', '定时任务名称')
        },
        { 
          title: 'Namespace', 
          dataIndex: 'namespace', 
          key: 'namespace',
          ...getColumnSearchProps('namespace', '命名空间')
        },
        { 
          title: 'Schedule', 
          dataIndex: 'schedule', 
          key: 'schedule',
          ...getColumnSearchProps('schedule', '调度表达式')
        }
      ]
    }
  };

  const renderSideMenu = () => (
    <Menu
      mode="inline"
      selectedKeys={activeKeys}
      style={{ height: '100%', borderRight: 0 }}
    >
      {Object.entries(resourceTables).map(([key, config]) => (
        <Menu.Item
          key={key}
          icon={config.icon}
          onClick={() => handleMenuClick(key)}
        >
          <Space>
            {config.title}
            <Badge count={getResourceCount(key)} style={{ backgroundColor: '#52c41a' }} />
          </Space>
        </Menu.Item>
      ))}
    </Menu>
  );

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ 
        background: '#fff', 
        padding: '0 24px', 
        boxShadow: '0 2px 8px #f0f1f2',
        position: 'sticky',
        top: 0,
        zIndex: 1,
        width: '100%',
        display: 'flex',
        alignItems: 'center'
      }}>
        <Row justify="space-between" align="middle" style={{ width: '100%' }}>
          <Col>
            <Space size="middle">
              <Button
                type="text"
                icon={<MenuOutlined />}
                onClick={() => setCollapsed(!collapsed)}
              />
              <Title level={3} style={{ margin: '16px 0', display: 'flex', alignItems: 'center' }}>
                <CloudServerOutlined style={{ marginRight: 8 }} />
                Kubernetes Resource Viewer
              </Title>
            </Space>
          </Col>
          <Col>
            <Space size="middle" style={{ display: 'flex', alignItems: 'center' }}>
              <Search
                placeholder="全局搜索"
                allowClear
                onChange={e => handleGlobalSearch(e.target.value)}
                style={{ 
                  width: 300,
                  margin: '0 16px'
                }}
                enterButton={<Button type="primary" icon={<SearchOutlined />}>搜索</Button>}
              />
              <Select
                style={{ 
                  width: 200,
                  marginRight: 16
                }}
                value={selectedCluster}
                onChange={setSelectedCluster}
                placeholder="选择集群"
              >
                {clusters.map(cluster => (
                  <Option key={cluster} value={cluster}>{cluster}</Option>
                ))}
              </Select>
              <Space>
                <Tooltip title="刷新">
                  <Button
                    type="primary"
                    icon={<ReloadOutlined />}
                    onClick={handleRefresh}
                    ghost
                  />
                </Tooltip>
                <Tooltip title="设置">
                  <Button
                    icon={<SettingOutlined />}
                    onClick={() => setDrawerVisible(true)}
                  />
                </Tooltip>
              </Space>
            </Space>
          </Col>
        </Row>
      </Header>
      <Layout>
        <Sider
          width={250}
          collapsible
          collapsed={collapsed}
          onCollapse={setCollapsed}
          theme="light"
          style={{ borderRight: '1px solid #f0f0f0' }}
        >
          {renderSideMenu()}
        </Sider>
        <Layout style={{ padding: '24px' }}>
          <Content style={{ background: '#fff', padding: 24, margin: 0, borderRadius: 8 }}>
            {activeKeys.map(key => {
              const config = resourceTables[key];
              return (
                <div key={key} style={{ marginBottom: 24 }}>
                  <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
                    <Col>
                      <Space>
                        {config.icon}
                        <Title level={4} style={{ margin: 0 }}>{config.title}</Title>
                        <Tag color="blue">{getResourceCount(key)}</Tag>
                      </Space>
                    </Col>
                  </Row>
                  <Table
                    columns={config.columns}
                    dataSource={filterData(resources[key] || [], key)}
                    rowKey="name"
                    pagination={{ pageSize: 10 }}
                    scroll={{ x: true }}
                    loading={loadingResources[key]}
                    size="middle"
                  />
                </div>
              );
            })}
            {activeKeys.length === 0 && (
              <div style={{ textAlign: 'center', padding: '48px 0' }}>
                <DashboardOutlined style={{ fontSize: 48, color: '#999' }} />
                <p style={{ color: '#999', marginTop: 16 }}>请从左侧菜单选择要查看的资源</p>
              </div>
            )}
          </Content>
        </Layout>
      </Layout>
      <Drawer
        title="设置"
        placement="right"
        onClose={() => setDrawerVisible(false)}
        visible={drawerVisible}
        width={360}
      >
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <div>
            <Title level={5}>自动刷新</Title>
            <Select
              style={{ width: '100%' }}
              value={refreshInterval}
              onChange={setRefreshInterval}
              placeholder="选择刷新间隔"
            >
              <Option value={null}>禁用</Option>
              <Option value={10}>10秒</Option>
              <Option value={30}>30秒</Option>
              <Option value={60}>1分钟</Option>
              <Option value={300}>5分钟</Option>
            </Select>
          </div>
          <div>
            <Title level={5}>显示的资源类型</Title>
            {Object.entries(resourceTables).map(([key, config]) => (
              <Tag
                key={key}
                color={activeKeys.includes(key) ? 'blue' : 'default'}
                style={{ margin: '4px', cursor: 'pointer' }}
                onClick={() => handleMenuClick(key)}
              >
                {config.title}
              </Tag>
            ))}
          </div>
        </Space>
      </Drawer>
    </Layout>
  );
}

export default App; 