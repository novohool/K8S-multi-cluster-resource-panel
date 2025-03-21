import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { 
  Layout, 
  Table, 
  Row, 
  Col, 
  Select, 
  Typography, 
  Input, 
  Space,
  Drawer,
  Button,
  Menu,
  Tag,
  Tooltip,
  Badge,
  Modal,
  message,
  Avatar,
  Dropdown
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
  FilterOutlined,
  SecurityScanOutlined,
  TeamOutlined,
  FileTextOutlined,
  CodeOutlined,
  KeyOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  UserOutlined,
  LogoutOutlined,
  DownOutlined
} from '@ant-design/icons';
import axios from 'axios';
import Login from './components/Login';
import ClusterSelector from './components/ClusterSelector';
import UserProfile from './components/UserProfile';
import SideMenu from './components/SideMenu';

const { Header, Content, Sider } = Layout;
const { Title } = Typography;
const { Option } = Select;
const { Search } = Input;

const API_BASE_URL = 'http://localhost:8000/api';

function App() {
  const [clusters, setClusters] = useState([]);
  const [selectedCluster, setSelectedCluster] = useState(null);
  const [resources, setResources] = useState({});
  const [loadingResources, setLoadingResources] = useState({});
  const [activeKeys, setActiveKeys] = useState([]);
  const [searchText, setSearchText] = useState({});
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedResourceTypes, setSelectedResourceTypes] = useState([]);
  const [collapsed, setCollapsed] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userPermissions, setUserPermissions] = useState({});
  const [currentPage, setCurrentPage] = useState({});
  const [totalItems, setTotalItems] = useState({});
  const [logModalVisible, setLogModalVisible] = useState(false);
  const [selectedPodLogs, setSelectedPodLogs] = useState('');
  const [terminalModalVisible, setTerminalModalVisible] = useState(false);
  const [selectedPodForTerminal, setSelectedPodForTerminal] = useState(null);
  const [token, setToken] = useState(() => localStorage.getItem('token'));
  const [username, setUsername] = useState(() => localStorage.getItem('username'));
  const [userProfileVisible, setUserProfileVisible] = useState(false);
  const [clusterStatus, setClusterStatus] = useState({});
  const menuRef = useRef(null);
  const PAGE_SIZE = 10;

  // 初始化时检查本地存储的认证信息
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    const storedUsername = localStorage.getItem('username');
    const storedPermissions = localStorage.getItem('userPermissions');
    
    if (storedToken && storedUsername) {
      setToken(storedToken);
      setUsername(storedUsername);
      if (storedPermissions) {
        try {
          const permissions = JSON.parse(storedPermissions);
          setUserPermissions(permissions);
          console.log('Loaded permissions:', permissions); // 添加日志
        } catch (error) {
          console.error('Error parsing stored permissions:', error);
          // 如果解析失败，设置默认权限
          const defaultPermissions = {
            canViewLogs: true,
            canExecPods: false
          };
          setUserPermissions(defaultPermissions);
          localStorage.setItem('userPermissions', JSON.stringify(defaultPermissions));
        }
      } else {
        // 如果没有存储的权限，设置默认权限
        const defaultPermissions = {
          canViewLogs: true,
          canExecPods: false
        };
        setUserPermissions(defaultPermissions);
        localStorage.setItem('userPermissions', JSON.stringify(defaultPermissions));
      }
    }
  }, []);

  useEffect(() => {
    // 只有在没有集群列表时才获取
    if (token && (!clusters || clusters.length === 0)) {
      fetchClusters();
    }
  }, [token]);

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
      const response = await axios.get(`${API_BASE_URL}/clusters`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      console.log('Received clusters:', response.data);
      // 确保集群列表中没有重复项
      const uniqueClusters = [...new Set(response.data.clusters)];
      setClusters(uniqueClusters);
      if (uniqueClusters.length > 0 && !selectedCluster) {
        console.log('Setting initial cluster:', uniqueClusters[0]);
        setSelectedCluster(uniqueClusters[0]);
        // 检查第一个集群的状态
        checkClusterStatus(uniqueClusters[0]);
      } else if (uniqueClusters.length === 0) {
        console.log('No clusters available');
        message.warning('您没有可访问的 Kubernetes 集群');
      }
    } catch (error) {
      console.error('Error fetching clusters:', error);
      if (error.response?.status === 401) {
        message.error('认证已失效，请重新登录');
        // 清除认证信息
        handleLogout();
      } else {
        message.error(`获取集群列表失败: ${error.response?.data?.detail?.message || error.message}`);
      }
    }
  };

  const checkClusterStatus = async (cluster) => {
    try {
      // 验证 kubeconfig
      const response = await axios.get(`${API_BASE_URL}/kubeconfig/${cluster}/validate`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      setClusterStatus(prev => ({
        ...prev,
        [cluster]: response.data.valid
      }));
    } catch (error) {
      console.error(`Error checking cluster status for ${cluster}:`, error);
      setClusterStatus(prev => ({
        ...prev,
        [cluster]: false
      }));
    }
  };

  const handleSearch = useCallback((selectedKeys, confirm, dataIndex) => {
    confirm();
    setSearchText(prev => ({
      ...prev,
      [dataIndex]: selectedKeys[0]
    }));
  }, []);

  const handleReset = useCallback((clearFilters, dataIndex) => {
    clearFilters();
    setSearchText(prev => ({
      ...prev,
      [dataIndex]: ''
    }));
  }, []);

  const handleLogin = async (username, password) => {
    try {
      const response = await axios.post(`${API_BASE_URL}/auth/login`, {
        username,
        password
      });

      const data = response.data;
      
      // 设置默认权限
      const defaultPermissions = {
        canViewLogs: true,  // 默认允许查看日志
        canExecPods: false  // 默认不允许执行终端
      };
      
      // 合并后端返回的权限和默认权限
      const permissions = {
        ...defaultPermissions,
        ...(data.permissions || {})
      };

      console.log('Setting permissions:', permissions); // 添加日志
      
      // 保存认证信息到本地存储
      localStorage.setItem('token', data.access_token);
      localStorage.setItem('username', username);
      localStorage.setItem('userPermissions', JSON.stringify(permissions));
      
      // 设置状态
      setToken(data.access_token);
      setUsername(username);
      setUserPermissions(permissions);
      
      message.success('登录成功');

      // 获取集群列表
      try {
        const clustersResponse = await axios.get(`${API_BASE_URL}/clusters`, {
          headers: {
            'Authorization': `Bearer ${data.access_token}`
          }
        });
        
        const authenticatedClusters = clustersResponse.data.clusters || [];
        setClusters(authenticatedClusters);
        
        if (authenticatedClusters.length > 0) {
          setSelectedCluster(authenticatedClusters[0]);
          // 检查第一个集群的状态
          checkClusterStatus(authenticatedClusters[0]);
        } else {
          message.warning('您没有可访问的 Kubernetes 集群');
        }
      } catch (error) {
        console.error('Error fetching clusters after login:', error);
        message.error(`获取集群列表失败: ${error.response?.data?.detail?.message || error.message}`);
      }
    } catch (error) {
      console.error('Login error:', error);
      if (error.response?.status === 401) {
        message.error('用户名或密码错误');
      } else {
        message.error(error.response?.data?.detail?.message || '登录失败');
      }
      throw error;
    }
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
  }), [handleSearch, handleReset, searchText]);

  const resourceTables = useMemo(() => ({
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
        },
        {
          title: 'Actions',
          key: 'actions',
          render: (_, record) => {
            console.log('Current permissions:', userPermissions);
            return (
              <Space>
                <Dropdown
                  menu={{
                    items: getContainerMenuItems(record)
                  }}
                >
                  <Button size="small">
                    Actions <DownOutlined />
                  </Button>
                </Dropdown>
              </Space>
            );
          }
        }
      ],
      expandable: {
        expandedRowRender: (record) => {
          const containerSections = [];
          
          // 添加初始化容器部分
          if (record.init_containers && record.init_containers.length > 0) {
            containerSections.push(
              <div key="init" style={{ marginBottom: '16px' }}>
                <Title level={5}>Init Containers</Title>
                <Table
                  dataSource={record.init_containers}
                  columns={[
                    {
                      title: 'Name',
                      dataIndex: 'name',
                      key: 'name'
                    },
                    {
                      title: 'Image',
                      dataIndex: 'image',
                      key: 'image'
                    },
                    {
                      title: 'Status',
                      dataIndex: 'status',
                      key: 'status',
                      render: (status) => (
                        <Tag color={status === 'Running' ? 'green' : 'default'}>
                          {status}
                        </Tag>
                      )
                    },
                    {
                      title: 'Actions',
                      key: 'actions',
                      render: (_, container) => (
                        <Space>
                          <Button
                            size="small"
                            icon={<FileTextOutlined />}
                            onClick={() => fetchPodLogs(record.name, record.namespace, container.name)}
                          >
                            Logs
                          </Button>
                          {userPermissions.canExecPods && (
                            <Button
                              size="small"
                              icon={<CodeOutlined />}
                              onClick={() => openTerminal(record, container.name)}
                            >
                              Terminal
                            </Button>
                          )}
                        </Space>
                      )
                    }
                  ]}
                  pagination={false}
                  size="small"
                />
              </div>
            );
          }
          
          // 添加主容器部分
          if (record.containers && record.containers.length > 0) {
            containerSections.push(
              <div key="main">
                <Title level={5}>Containers</Title>
                <Table
                  dataSource={record.containers}
                  columns={[
                    {
                      title: 'Name',
                      dataIndex: 'name',
                      key: 'name'
                    },
                    {
                      title: 'Image',
                      dataIndex: 'image',
                      key: 'image'
                    },
                    {
                      title: 'Status',
                      dataIndex: 'status',
                      key: 'status',
                      render: (status) => (
                        <Tag color={status === 'Running' ? 'green' : 'default'}>
                          {status}
                        </Tag>
                      )
                    },
                    {
                      title: 'Actions',
                      key: 'actions',
                      render: (_, container) => (
                        <Space>
                          <Button
                            size="small"
                            icon={<FileTextOutlined />}
                            onClick={() => fetchPodLogs(record.name, record.namespace, container.name)}
                          >
                            Logs
                          </Button>
                          {userPermissions.canExecPods && (
                            <Button
                              size="small"
                              icon={<CodeOutlined />}
                              onClick={() => openTerminal(record, container.name)}
                            >
                              Terminal
                            </Button>
                          )}
                        </Space>
                      )
                    }
                  ]}
                  pagination={false}
                  size="small"
                />
              </div>
            );
          }
          
          return (
            <div style={{ padding: '0 20px' }}>
              {containerSections}
            </div>
          );
        }
      }
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
  }), [getColumnSearchProps]);

  const additionalResourceTables = useMemo(() => ({
    serviceaccounts: {
      title: 'Service Accounts',
      icon: <TeamOutlined />,
      columns: [
        {
          title: 'Name',
          dataIndex: 'name',
          key: 'name',
          ...getColumnSearchProps('name', 'Service Account Name'),
        },
        {
          title: 'Namespace',
          dataIndex: 'namespace',
          key: 'namespace',
          ...getColumnSearchProps('namespace', 'Namespace'),
        },
        {
          title: 'Created',
          dataIndex: 'created',
          key: 'created',
        }
      ]
    },
    
    clusterroles: {
      title: 'Cluster Roles',
      icon: <SecurityScanOutlined />,
      columns: [
        {
          title: 'Name',
          dataIndex: 'name',
          key: 'name',
          ...getColumnSearchProps('name', 'Cluster Role Name'),
        },
        {
          title: 'Created',
          dataIndex: 'created',
          key: 'created',
        }
      ]
    },

    clusterrolebindings: {
      title: 'Cluster Role Bindings',
      icon: <SecurityScanOutlined />,
      columns: [
        {
          title: 'Name',
          dataIndex: 'name',
          key: 'name',
          ...getColumnSearchProps('name', 'Binding Name'),
        },
        {
          title: 'Role Ref',
          dataIndex: 'roleRef',
          key: 'roleRef',
        },
        {
          title: 'Subjects',
          dataIndex: 'subjects',
          key: 'subjects',
          render: subjects => subjects.map(s => 
            <Tag key={`${s.kind}-${s.name}`}>{`${s.kind}: ${s.name}`}</Tag>
          )
        }
      ]
    },

    configmaps: {
      title: 'Config Maps',
      icon: <FileTextOutlined />,
      columns: [
        {
          title: 'Name',
          dataIndex: 'name',
          key: 'name',
          ...getColumnSearchProps('name', 'Config Map Name'),
        },
        {
          title: 'Namespace',
          dataIndex: 'namespace',
          key: 'namespace',
          ...getColumnSearchProps('namespace', 'Namespace'),
        },
        {
          title: 'Data Keys',
          dataIndex: 'dataKeys',
          key: 'dataKeys',
          render: keys => keys.map(key => <Tag key={key}>{key}</Tag>)
        }
      ]
    },

    secrets: {
      title: 'Secrets',
      icon: <KeyOutlined />,
      columns: [
        {
          title: 'Name',
          dataIndex: 'name',
          key: 'name',
          ...getColumnSearchProps('name', 'Secret Name'),
        },
        {
          title: 'Namespace',
          dataIndex: 'namespace',
          key: 'namespace',
          ...getColumnSearchProps('namespace', 'Namespace'),
        },
        {
          title: 'Type',
          dataIndex: 'type',
          key: 'type',
          ...getColumnSearchProps('type', 'Secret Type'),
        },
        {
          title: 'TLS Expiration',
          dataIndex: 'tls_expiration',
          key: 'tls_expiration',
          render: (text, record) => {
            if (record.type !== 'kubernetes.io/tls' || !record.tls_expiration) {
              return '-';
            }
            
            const expirationDate = new Date(record.tls_expiration);
            const formattedDate = expirationDate.toLocaleDateString();
            const daysUntilExpiry = record.days_until_expiry;
            
            let color = 'green';
            let icon = <CheckCircleOutlined />;
            
            if (record.is_expired) {
              color = 'red';
              icon = <WarningOutlined />;
            } else if (daysUntilExpiry <= 30) {
              color = 'orange';
              icon = <WarningOutlined />;
            }
            
            return (
              <Tag color={color} icon={icon}>
                {formattedDate} ({daysUntilExpiry} days)
              </Tag>
            );
          }
        }
      ]
    }
  }), [getColumnSearchProps]);

  const mergedResourceTables = useMemo(() => ({
    ...resourceTables,
    ...additionalResourceTables
  }), [resourceTables, additionalResourceTables]);

  const getResourceTitle = useCallback((resourceType) => {
    return mergedResourceTables[resourceType]?.title || resourceType;
  }, [mergedResourceTables]);

  const getContainerMenuItems = useCallback((record) => {
    const items = [];
    
    // 添加初始化容器的菜单项
    if (record.init_containers && record.init_containers.length > 0) {
      items.push({
        key: 'init-containers',
        type: 'group',
        label: 'Init Containers',
        children: record.init_containers.map(container => ({
          key: `init-${container.name}`,
          type: 'group',
          label: container.name,
          children: [
            {
              key: `init-${container.name}-logs`,
              label: 'Logs',
              icon: <FileTextOutlined />,
              onClick: () => fetchPodLogs(record.name, record.namespace, container.name)
            },
            userPermissions.canExecPods && {
              key: `init-${container.name}-terminal`,
              label: 'Terminal',
              icon: <CodeOutlined />,
              onClick: () => openTerminal(record, container.name)
            }
          ].filter(Boolean)
        }))
      });
    }
    
    // 添加主容器的菜单项
    if (record.containers && record.containers.length > 0) {
      items.push({
        key: 'containers',
        type: 'group',
        label: 'Containers',
        children: record.containers.map(container => ({
          key: container.name,
          type: 'group',
          label: container.name,
          children: [
            {
              key: `${container.name}-logs`,
              label: 'Logs',
              icon: <FileTextOutlined />,
              onClick: () => fetchPodLogs(record.name, record.namespace, container.name)
            },
            userPermissions.canExecPods && {
              key: `${container.name}-terminal`,
              label: 'Terminal',
              icon: <CodeOutlined />,
              onClick: () => openTerminal(record, container.name)
            }
          ].filter(Boolean)
        }))
      });
    }
    
    return items;
  }, [userPermissions]);

  const fetchPodLogs = useCallback(async (podName, namespace, containerName) => {
    try {
      const response = await axios.get(
        `${API_BASE_URL}/pods/${selectedCluster}/${namespace}/${podName}/logs`,
        {
          headers: {
            'Authorization': `Bearer ${token}`
          },
          params: {
            container: containerName
          }
        }
      );
      // 确保我们获取到的是日志字符串
      const logContent = response.data.logs || response.data;
      setSelectedPodLogs(typeof logContent === 'string' ? logContent : JSON.stringify(logContent));
      setLogModalVisible(true);
    } catch (error) {
      console.error('Error fetching pod logs:', error);
      message.error(`获取日志失败: ${error.response?.data?.detail?.message || error.message}`);
    }
  }, [token, selectedCluster]);

  const openTerminal = useCallback((pod, containerName) => {
    setSelectedPodForTerminal({ ...pod, containerName });
    setTerminalModalVisible(true);
  }, []);

  const handleLogout = useCallback(() => {
    // 清除所有状态
    setToken(null);
    setUsername(null);
    setUserPermissions({});
    setClusters([]);
    setSelectedCluster(null);
    setUserProfileVisible(false);
    
    // 清除本地存储
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    localStorage.removeItem('userPermissions');
    
    message.success('已退出登录');
  }, []);

  const fetchResourceType = useCallback(async (cluster, resourceType, page = 1, silent = false) => {
    if (!cluster) return;

    setLoadingResources(prev => ({ ...prev, [resourceType]: !silent }));
    try {
      const response = await axios.get(`${API_BASE_URL}/resources/${cluster}/${resourceType}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        },
        params: {
          page,
          page_size: PAGE_SIZE
        }
      });

      // 检查响应数据的结构
      const responseData = response.data;
      let items = [];
      let total = 0;

      if (Array.isArray(responseData)) {
        // 如果响应是数组，说明是旧格式
        items = responseData;
        total = responseData.length;
      } else if (responseData.items && Array.isArray(responseData.items)) {
        // 如果响应包含 items 字段，说明是新的分页格式
        items = responseData.items;
        total = responseData.total || responseData.items.length;
      } else {
        // 如果都不是，可能是错误的响应格式
        console.error('Unexpected response format:', responseData);
        items = [];
        total = 0;
      }

      // 更新资源数据
      setResources(prev => ({
        ...prev,
        [resourceType]: items
      }));

      // 更新总数
      setTotalItems(prev => ({
        ...prev,
        [resourceType]: total
      }));

      if (!silent) {
        message.success(`${getResourceTitle(resourceType)} 加载成功`);
      }
      // 如果资源获取成功，说明连接是正常的
      setClusterStatus(prev => ({
        ...prev,
        [cluster]: true
      }));
    } catch (error) {
      console.error(`Error fetching ${resourceType}:`, error);
      if (!silent) {
        if (error.response?.status === 401) {
          message.error(`获取 ${getResourceTitle(resourceType)} 失败：认证已失效，请刷新配置`);
          // 更新集群状态
          setClusterStatus(prev => ({
            ...prev,
            [cluster]: false
          }));
        } else {
          message.error(`获取 ${getResourceTitle(resourceType)} 失败: ${error.message}`);
        }
      }
      setResources(prev => ({ ...prev, [resourceType]: [] }));
      setTotalItems(prev => ({ ...prev, [resourceType]: 0 }));
    } finally {
      setLoadingResources(prev => ({ ...prev, [resourceType]: false }));
    }
  }, [token, getResourceTitle]);

  useEffect(() => {
    if (selectedResourceTypes.length > 0 && selectedCluster) {
      selectedResourceTypes.forEach(type => {
        fetchResourceType(selectedCluster, type);
      });
    }
  }, [selectedResourceTypes, selectedCluster, fetchResourceType]);

  useEffect(() => {
    if (refreshInterval && selectedCluster) {
      const timer = setInterval(() => {
        activeKeys.forEach(key => {
          fetchResourceType(selectedCluster, key, 1, true);
        });
      }, refreshInterval * 1000);
      return () => clearInterval(timer);
    }
  }, [refreshInterval, selectedCluster, activeKeys, fetchResourceType]);

  const handlePageChange = (page, resourceType) => {
    setCurrentPage(prev => ({ ...prev, [resourceType]: page }));
    fetchResourceType(selectedCluster, resourceType, page, true);
  };

  const handleMenuClick = (resourceType) => {
    const newKeys = activeKeys.includes(resourceType)
      ? activeKeys.filter(key => key !== resourceType)
      : [...activeKeys, resourceType];
    setActiveKeys(newKeys);
    if (!activeKeys.includes(resourceType)) {
      // 重置页码并获取第一页数据
      setCurrentPage(prev => ({ ...prev, [resourceType]: 1 }));
      fetchResourceType(selectedCluster, resourceType, 1);
    }
  };

  const getResourceCount = (resourceType) => {
    return resources[resourceType]?.length || 0;
  };

  const handleRefresh = () => {
    if (selectedCluster) {
      activeKeys.forEach(key => {
        const currentPageForKey = currentPage[key] || 1;
        fetchResourceType(selectedCluster, key, currentPageForKey, true);
      });
      message.success('正在刷新资源...');
    }
  };

  const handleSideMenuClick = (key) => {
    handleMenuClick(key);
  };

  const handleClusterChange = (value) => {
    setSelectedCluster(value);
    // 清空资源数据
    setResources({});
    setActiveKeys([]);
    // 检查新选择的集群状态
    checkClusterStatus(value);
  };

  if (!token) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ background: '#fff', padding: 0, height: 'auto' }}>
        <Row justify="space-between" align="middle" style={{ padding: '0 24px' }}>
          <Col>
            <Space>
              <Button
                type="text"
                icon={<MenuOutlined />}
                onClick={() => setCollapsed(!collapsed)}
                style={{ fontSize: '16px', width: 64, height: 64 }}
              />
              <Title level={4} style={{ margin: 0 }}>Kubernetes 资源面板</Title>
            </Space>
          </Col>
          <Col>
            <Space>
              <Select
                value={selectedCluster}
                onChange={handleClusterChange}
                style={{ width: 200 }}
                placeholder="选择集群"
              >
                {clusters.map(cluster => (
                  <Option key={cluster} value={cluster}>
                    {cluster}
                  </Option>
                ))}
              </Select>
              {selectedCluster && clusterStatus[selectedCluster] !== undefined && (
                <Badge
                  status={clusterStatus[selectedCluster] ? "success" : "error"}
                  text={clusterStatus[selectedCluster] ? "已连接" : "未连接"}
                />
              )}
              <Tooltip title="刷新">
                <Button
                  type="text"
                  icon={<ReloadOutlined />}
                  onClick={handleRefresh}
                />
              </Tooltip>
              <Tooltip title="设置">
                <Button
                  type="text"
                  icon={<SettingOutlined />}
                  onClick={() => setDrawerVisible(true)}
                />
              </Tooltip>
              <Dropdown
                overlay={
                  <Menu>
                    <Menu.Item key="profile" onClick={() => setUserProfileVisible(true)}>
                      <UserOutlined /> 用户信息
                    </Menu.Item>
                    <Menu.Item key="logout" onClick={handleLogout}>
                      <LogoutOutlined /> 退出登录
                    </Menu.Item>
                  </Menu>
                }
              >
                <Button type="text">
                  <Space>
                    <Avatar size="small" icon={<UserOutlined />} />
                    {username}
                  </Space>
                </Button>
              </Dropdown>
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
          <SideMenu
            ref={menuRef}
            activeKeys={activeKeys}
            resourceTables={mergedResourceTables}
            onMenuClick={handleSideMenuClick}
            getResourceCount={getResourceCount}
          />
        </Sider>
        <Layout style={{ padding: '24px' }}>
          <Content style={{ background: '#fff', padding: 24, margin: 0, borderRadius: 8 }}>
            {activeKeys.map(key => {
              const config = mergedResourceTables[key];
              return (
                <div key={key} style={{ marginBottom: 24 }}>
                  <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
                    <Col>
                      <Space>
                        {config.icon}
                        <Title level={4} style={{ margin: 0 }}>{config.title}</Title>
                        <Tag color="blue">{totalItems[key] || 0}</Tag>
                      </Space>
                    </Col>
                  </Row>
                  <Table
                    columns={config.columns}
                    dataSource={resources[key] || []}
                    rowKey="name"
                    pagination={{
                      current: currentPage[key] || 1,
                      pageSize: PAGE_SIZE,
                      total: totalItems[key] || 0,
                      onChange: (page) => handlePageChange(page, key)
                    }}
                    scroll={{ x: true }}
                    loading={loadingResources[key]}
                    size="middle"
                    expandable={config.expandable}
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
            {Object.entries(mergedResourceTables).map(([key, config]) => (
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
      <Drawer
        title={`用户设置 - ${username}`}
        placement="right"
        onClose={() => setUserProfileVisible(false)}
        visible={userProfileVisible}
        width={1200}
        bodyStyle={{ padding: '16px' }}
      >
        <UserProfile 
          token={token}
          username={username}
          clusters={clusters}
        />
      </Drawer>
      <Modal
        title="Pod Logs"
        visible={logModalVisible}
        onCancel={() => setLogModalVisible(false)}
        width={800}
        footer={null}
      >
        <pre style={{ maxHeight: '500px', overflow: 'auto', whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>
          {selectedPodLogs}
        </pre>
      </Modal>
      <Modal
        title={`Terminal - ${selectedPodForTerminal?.name} - ${selectedPodForTerminal?.containerName}`}
        visible={terminalModalVisible}
        onCancel={() => setTerminalModalVisible(false)}
        width={800}
        footer={null}
      >
        <div style={{ height: '400px', backgroundColor: '#000', color: '#fff', padding: '10px' }}>
          {/* Terminal implementation would go here */}
          {/* You'll need to implement WebSocket connection to the backend for terminal functionality */}
        </div>
      </Modal>
    </Layout>
  );
}

export default App;