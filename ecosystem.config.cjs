module.exports = {
  apps: [
    {
      name: 'bughunter-api',
      script: 'python3',
      args: '/home/user/webapp/api/app.py',
      cwd: '/home/user/webapp',
      env: {
        PYTHONUNBUFFERED: '1',
        FLASK_ENV: 'production'
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork',
      restart_delay: 2000,
      max_restarts: 5
    },
    {
      name: 'bughunter-frontend',
      script: 'python3',
      args: '/home/user/webapp/server.py',
      cwd: '/home/user/webapp',
      env: {
        PYTHONUNBUFFERED: '1'
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork',
      restart_delay: 2000,
      max_restarts: 5
    }
  ]
};
