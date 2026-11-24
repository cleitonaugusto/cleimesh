FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --break-system-packages "mcp>=1.2,<2" mcp-server-fetch && ln -s /usr/bin/python3 /usr/local/bin/python
RUN npm install -g @modelcontextprotocol/server-filesystem && npm cache clean --force
COPY cleimesh /usr/local/bin/cleimesh
COPY run.sh driver.py /app/
WORKDIR /app
CMD ["bash","run.sh"]
