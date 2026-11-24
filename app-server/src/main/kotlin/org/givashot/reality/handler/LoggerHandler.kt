package org.givashot.reality.handler

import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import org.givashot.reality.CONNECTION_NUM_KEY
import org.givashot.reality.handler.VlessDuplexHandler.Companion.TARGET_KEY
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class LoggerHandler : ChannelDuplexHandler() {

    private var context: ChannelHandlerContext? = null
    private var connLogger: Logger? = null
    private var connTargetLogger: Logger? = null

    private val logger: Logger get()  {
        return if (connTargetLogger != null) {
            connTargetLogger!!
        } else {
            if (context!!.channel().hasAttr(TARGET_KEY)) {
                connLogger = null
                connTargetLogger = LoggerFactory.getLogger("LoggerHandler" +
                        "#${context!!.channel().attr(CONNECTION_NUM_KEY).get()}" +
                        "#${context!!.channel().attr(TARGET_KEY).get()}")
                connTargetLogger!!
            } else {
                if (connLogger == null) {
                    connLogger = LoggerFactory.getLogger("LoggerHandler" +
                            "#${context!!.channel().attr(CONNECTION_NUM_KEY).get()}")
                }
                connLogger!!
            }
        }
    }

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        context = ctx
    }

    override fun channelRead(ctx: ChannelHandlerContext?, msg: Any?) {
        logMessage("read", msg)
        super.channelRead(ctx, msg)
    }

    override fun write(ctx: ChannelHandlerContext?, msg: Any?, promise: ChannelPromise?) {
        logMessage("write", msg)
        super.write(ctx, msg, promise)
    }

    private fun logMessage(direction: String, msg: Any?) {
        if (msg is ByteBuf) {
            val length = msg.readableBytes()
            val dumpMsg = {
                val maxDumpSize = if (logger.isDebugEnabled) Int.MAX_VALUE else 100
                "{$direction} -> length={$length}, dumpBytes={${
                    ByteBufUtil.hexDump(
                        msg,
                        msg.readerIndex(),
                        minOf(length, maxDumpSize)
                    )
                }}"
            }
            if (logger.isDebugEnabled) {
                logger.debug(dumpMsg.invoke())
            } else {
                logger.atInfo().log(dumpMsg)
            }
        } else {
            logger.atInfo().log {
                "{$direction} -> {$msg}"
            }
        }
    }

}