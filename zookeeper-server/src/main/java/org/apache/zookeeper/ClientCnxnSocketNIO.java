/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.LinkedList;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;

import org.apache.zookeeper.ClientCnxn.EndOfStreamException;
import org.apache.zookeeper.ClientCnxn.Packet;
import org.apache.zookeeper.ZooDefs.OpCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientCnxnSocketNIO extends ClientCnxnSocket {
    private static final Logger LOG = LoggerFactory
            .getLogger(ClientCnxnSocketNIO.class);

    private final Selector selector = Selector.open();

    private SelectionKey sockKey;

    ClientCnxnSocketNIO() throws IOException {
        super();
    }

    @Override
    boolean isConnected() {
        return sockKey != null;
    }
    
    /**
     * @return true if a packet was received
     * @throws InterruptedException
     * @throws IOException
     */
    void doIO(List<Packet> pendingQueue, LinkedList<Packet> outgoingQueue, ClientCnxn cnxn)
      throws InterruptedException, IOException {
        SocketChannel sock = (SocketChannel) sockKey.channel();
        if (sock == null) {
            throw new IOException("Socket is null!");
        }
        if (sockKey.isReadable()) {
            // 第一次只读取四个字节， 因为这个时候 incomingBuffer == lenBuffer ， 只能存储四个字节的数据
            // 第二次根据第一次读取到的 len , 再次读取字节
            int rc = sock.read(incomingBuffer);
            if (rc < 0) {
                throw new EndOfStreamException(
                        "Unable to read additional data from server sessionid 0x"
                                + Long.toHexString(sessionId)
                                + ", likely server has closed socket");
            }
            if (!incomingBuffer.hasRemaining()) { // 没有剩余， 代表读取到了 四个字节， 继续向下操作。
                incomingBuffer.flip();   // 反转读写模式
                if (incomingBuffer == lenBuffer) {  // 等于的话，代表读取的就是第一次读取
                    recvCount++;
                    readLength();     // 根据读取到的 len , 重新分配一个新的buffer给 incomingBuffer
                } else if (!initialized) {   // 如果没有初始化完成， 那么就读取 ConnectResult，
                    readConnectResult();  // 在这里，读取到了一个 SessionId
                    enableRead();
                    if (findSendablePacket(outgoingQueue,
                            cnxn.sendThread.clientTunneledAuthenticationInProgress()) != null) {
                        // Since SASL authentication has completed (if client is configured to do so),
                        // outgoing packets waiting in the outgoingQueue can now be sent.
                        // 如果有可以发送的 packet , 那么就 enableWrite
                        enableWrite();
                    }
                    // 清空lenBuffer， 准备好下一次读取数据。
                    lenBuffer.clear();
                    incomingBuffer = lenBuffer;
                    updateLastHeard();
                    initialized = true;
                } else {
                    // 将读取到的 incomingBuffer ， 交给 sendThread 进行处理
                    sendThread.readResponse(incomingBuffer);
                    lenBuffer.clear();
                    incomingBuffer = lenBuffer;
                    updateLastHeard();
                }
            }
        }
        if (sockKey.isWritable()) {
            synchronized(outgoingQueue) {
                // 找到第一个可以发送的Packet ， 1. 发半包的 2. 还在处理 sasl 的， 3. 正常等待发送的
                Packet p = findSendablePacket(outgoingQueue,
                        cnxn.sendThread.clientTunneledAuthenticationInProgress());

                if (p != null) {
                    updateLastSend();
                    // If we already started writing p, p.bb will already exist
                    if (p.bb == null) {
                        if ((p.requestHeader != null) &&
                                (p.requestHeader.getType() != OpCode.ping) &&
                                (p.requestHeader.getType() != OpCode.auth)) {
                            p.requestHeader.setXid(cnxn.getXid());
                        }
                        // 如果 Packet 的 bytebuffer为空， 那么就要进行生成。生成了 Packet 对应的 bytebuffer
                        p.createBB();
                    }
                    // 将bytebuffer发送出去
                    sock.write(p.bb);
                    if (!p.bb.hasRemaining()) {
                        // 如果没有剩余的包没发出去的话，就将这个packet从outgoingQueue中删除，并加入到 pendingQueue中。
                        sentCount++;
                        outgoingQueue.removeFirstOccurrence(p);
                        if (p.requestHeader != null
                                && p.requestHeader.getType() != OpCode.ping
                                && p.requestHeader.getType() != OpCode.auth) {
                            synchronized (pendingQueue) {
                                pendingQueue.add(p);
                            }
                        }
                    }
                }
                if (outgoingQueue.isEmpty()) {
                    // No more packets to send: turn off write interest flag.
                    // Will be turned on later by a later call to enableWrite(),
                    // from within ZooKeeperSaslClient (if client is configured
                    // to attempt SASL authentication), or in either doIO() or
                    // in doTransport() if not.
                    // 如果 outgoingQueue 为空， 那么就没必要监听 OP_WRITE 事件了
                    disableWrite();
                } else if (!initialized && p != null && !p.bb.hasRemaining()) {
                    // On initial connection, write the complete connect request
                    // packet, but then disable further writes until after
                    // receiving a successful connection response.  If the
                    // session is expired, then the server sends the expiration
                    // response and immediately closes its end of the socket.  If
                    // the client is simultaneously writing on its end, then the
                    // TCP stack may choose to abort with RST, in which case the
                    // client would never receive the session expired event.  See
                    // http://docs.oracle.com/javase/6/docs/technotes/guides/net/articles/connection_release.html
                    // 如果没有初始化完成 并且 没有发半包的情况，那么也没必要监听 OP_WRITE 事件了
                    disableWrite();
                } else {
                    // Just in case  以防万一， 其实也就是没必要
                    enableWrite();
                }
            }
        }
    }

    private Packet findSendablePacket(LinkedList<Packet> outgoingQueue,
                                      boolean clientTunneledAuthenticationInProgress) {
        synchronized (outgoingQueue) {
            if (outgoingQueue.isEmpty()) {
                return null;
            }
            if (outgoingQueue.getFirst().bb != null // If we've already starting sending the first packet, we better finish
                || !clientTunneledAuthenticationInProgress) {
                // 1. 只发半包，sasl请求已经处理完了， 直接返回第一个
                return outgoingQueue.getFirst();
            }

            // Since client's authentication with server is in progress,
            // send only the null-header packet queued by primeConnection().
            // This packet must be sent so that the SASL authentication process
            // can proceed, but all other packets should wait until
            // SASL authentication completes.
            // 首先发送 没有header头的 sasl 请求
            ListIterator<Packet> iter = outgoingQueue.listIterator();
            while (iter.hasNext()) {
                Packet p = iter.next();
                if (p.requestHeader == null) {
                    // We've found the priming-packet. Move it to the beginning of the queue.
                    iter.remove();
                    outgoingQueue.add(0, p);
                    return p;
                } else {
                    // Non-priming packet: defer it until later, leaving it in the queue
                    // until authentication completes.
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("deferring non-priming packet: " + p +
                                "until SASL authentication completes.");
                    }
                }
            }
            // no sendable packet found.
            return null;
        }
    }

    @Override
    void cleanup() {
        if (sockKey != null) {
            SocketChannel sock = (SocketChannel) sockKey.channel();
            sockKey.cancel();
            try {
                sock.socket().shutdownInput();
            } catch (IOException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Ignoring exception during shutdown input", e);
                }
            }
            try {
                sock.socket().shutdownOutput();
            } catch (IOException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Ignoring exception during shutdown output",
                            e);
                }
            }
            try {
                sock.socket().close();
            } catch (IOException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Ignoring exception during socket close", e);
                }
            }
            try {
                sock.close();
            } catch (IOException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Ignoring exception during channel close", e);
                }
            }
        }
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("SendThread interrupted during sleep, ignoring");
            }
        }
        sockKey = null;
    }
 
    @Override
    void close() {
        try {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Doing client selector close");
            }
            selector.close();
            if (LOG.isTraceEnabled()) {
                LOG.trace("Closed client selector");
            }
        } catch (IOException e) {
            LOG.warn("Ignoring exception during selector close", e);
        }
    }
    
    /**
     * create a socket channel.
     * @return the created socket channel
     * @throws IOException
     */
    SocketChannel createSock() throws IOException {
        SocketChannel sock;
        sock = SocketChannel.open();
        sock.configureBlocking(false);
        sock.socket().setSoLinger(false, -1);
        sock.socket().setTcpNoDelay(true);
        return sock;
    }

    /**
     * register with the selection and connect
     * @param sock the {@link SocketChannel} 
     * @param addr the address of remote host
     * @throws IOException
     */
    void registerAndConnect(SocketChannel sock, InetSocketAddress addr) 
    throws IOException {
        sockKey = sock.register(selector, SelectionKey.OP_CONNECT);
        boolean immediateConnect = sock.connect(addr);
        if (immediateConnect) {
            sendThread.primeConnection();
        }
    }
    
    @Override
    void connect(InetSocketAddress addr) throws IOException {
        SocketChannel sock = createSock();
        try {
           registerAndConnect(sock, addr);
        } catch (IOException e) {
            LOG.error("Unable to open socket to " + addr);
            sock.close();
            throw e;
        }
        initialized = false;

        /*
         * Reset incomingBuffer
         */
        lenBuffer.clear();
        incomingBuffer = lenBuffer;
    }

    /**
     * Returns the address to which the socket is connected.
     * 
     * @return ip address of the remote side of the connection or null if not
     *         connected
     */
    @Override
    SocketAddress getRemoteSocketAddress() {
        // a lot could go wrong here, so rather than put in a bunch of code
        // to check for nulls all down the chain let's do it the simple
        // yet bulletproof way
        try {
            return ((SocketChannel) sockKey.channel()).socket()
                    .getRemoteSocketAddress();
        } catch (NullPointerException e) {
            return null;
        }
    }

    /**
     * Returns the local address to which the socket is bound.
     * 
     * @return ip address of the remote side of the connection or null if not
     *         connected
     */
    @Override
    SocketAddress getLocalSocketAddress() {
        // a lot could go wrong here, so rather than put in a bunch of code
        // to check for nulls all down the chain let's do it the simple
        // yet bulletproof way
        try {
            return ((SocketChannel) sockKey.channel()).socket()
                    .getLocalSocketAddress();
        } catch (NullPointerException e) {
            return null;
        }
    }

    @Override
    synchronized void wakeupCnxn() {
        selector.wakeup();
    }
    
    @Override
    void doTransport(int waitTimeOut, List<Packet> pendingQueue, LinkedList<Packet> outgoingQueue,
                     ClientCnxn cnxn)
            throws IOException, InterruptedException {
        selector.select(waitTimeOut);
        Set<SelectionKey> selected;
        synchronized (this) {
            selected = selector.selectedKeys();
        }
        // Everything below and until we get back to the select is
        // non blocking, so time is effectively a constant. That is
        // Why we just have to do this once, here
        updateNow();
        for (SelectionKey k : selected) {
            SocketChannel sc = ((SocketChannel) k.channel());
            if ((k.readyOps() & SelectionKey.OP_CONNECT) != 0) {
                if (sc.finishConnect()) {
                    updateLastSendAndHeard();
                    sendThread.primeConnection();
                }
            } else if ((k.readyOps() & (SelectionKey.OP_READ | SelectionKey.OP_WRITE)) != 0) {
                doIO(pendingQueue, outgoingQueue, cnxn);
            }
        }
        if (sendThread.getZkState().isConnected()) {
            synchronized(outgoingQueue) {
                if (findSendablePacket(outgoingQueue,
                        cnxn.sendThread.clientTunneledAuthenticationInProgress()) != null) {
                    enableWrite();
                }
            }
        }
        selected.clear();
    }

    //TODO should this be synchronized?
    @Override
    void testableCloseSocket() throws IOException {
        LOG.info("testableCloseSocket() called");
        ((SocketChannel) sockKey.channel()).socket().close();
    }

    @Override
    synchronized void enableWrite() {
        int i = sockKey.interestOps();
        if ((i & SelectionKey.OP_WRITE) == 0) {
            sockKey.interestOps(i | SelectionKey.OP_WRITE);
        }
    }

    @Override
    public synchronized void disableWrite() {
        int i = sockKey.interestOps();
        if ((i & SelectionKey.OP_WRITE) != 0) {
            sockKey.interestOps(i & (~SelectionKey.OP_WRITE));
        }
    }

    synchronized private void enableRead() {
        int i = sockKey.interestOps();
        if ((i & SelectionKey.OP_READ) == 0) {
            sockKey.interestOps(i | SelectionKey.OP_READ);
        }
    }

    @Override
    synchronized void enableReadWriteOnly() {
        sockKey.interestOps(SelectionKey.OP_READ | SelectionKey.OP_WRITE);
    }

    Selector getSelector() {
        return selector;
    }

    @Override
    void sendPacket(Packet p) throws IOException {
        SocketChannel sock = (SocketChannel) sockKey.channel();
        if (sock == null) {
            throw new IOException("Socket is null!");
        }
        p.createBB();
        ByteBuffer pbb = p.bb;
        sock.write(pbb);
    }


}
