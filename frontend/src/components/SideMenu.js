import React, { forwardRef } from 'react';
import { Menu, Space, Badge } from 'antd';

const SideMenu = forwardRef(({ 
  activeKeys, 
  resourceTables, 
  onMenuClick, 
  getResourceCount 
}, ref) => {
  return (
    <Menu
      mode="inline"
      selectedKeys={activeKeys}
      style={{ height: '100%', borderRight: 0 }}
      ref={ref}
    >
      {Object.entries(resourceTables).map(([key, config]) => (
        <Menu.Item
          key={key}
          icon={config.icon}
          onClick={() => onMenuClick(key)}
        >
          <Space>
            {config.title}
            <Badge count={getResourceCount(key)} style={{ backgroundColor: '#52c41a' }} />
          </Space>
        </Menu.Item>
      ))}
    </Menu>
  );
});

SideMenu.displayName = 'SideMenu';

export default SideMenu; 