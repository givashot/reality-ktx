package org.givashot.reality.handler

import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import org.givashot.reality.CONNECTION_NUM_KEY
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class LoggerHandler : ChannelDuplexHandler() {

    private lateinit var logger: Logger

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        logger = LoggerFactory.getLogger("LoggerHandler#${ctx.channel().attr(CONNECTION_NUM_KEY).get()}")
    }

    override fun channelRead(ctx: ChannelHandlerContext?, msg: Any?) {
        if (logger.isInfoEnabled) {
            logMessage("read", msg)
        }
        super.channelRead(ctx, msg)
    }

    override fun write(ctx: ChannelHandlerContext?, msg: Any?, promise: ChannelPromise?) {
        if (logger.isInfoEnabled) {
            logMessage("write", msg)
        }
        super.write(ctx, msg, promise)
    }

    private fun logMessage(direction: String, msg: Any?) {
        if (msg is ByteBuf) {
            val length = msg.readableBytes()
            val prefix = ByteBufUtil.hexDump(msg, msg.readerIndex(), minOf(length, Int.MAX_VALUE))
            logger.info("{} -> length={}, firstBytes={}", direction, length, prefix)
        } else {
            logger.info("{} -> {}", direction, msg)
        }
    }

}