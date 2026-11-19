package com.readroid.app.core.analyzer



import org.junit.Assert.assertEquals

import org.junit.Assert.assertThrows

import org.junit.Assert.assertTrue

import org.junit.Rule

import org.junit.Test

import org.junit.rules.TemporaryFolder

import java.io.ByteArrayOutputStream

import java.util.zip.ZipEntry

import java.util.zip.ZipOutputStream



class DexMethodBodyTest {



    @get:Rule

    val tmp = TemporaryFolder()



    /** DEX sintético com uma classe e um método com corpo (return-void). */

    private fun buildDexWithMethodBody(): ByteArray {

        val out = java.io.ByteArrayOutputStream()

        val h = java.nio.ByteBuffer.allocate(112).order(java.nio.ByteOrder.LITTLE_ENDIAN)

        h.put(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00))
        h.putInt(0); h.put(ByteArray(20)); h.putInt(0); h.putInt(112); h.putInt(0x12345678)

        h.putInt(0); h.putInt(0); h.putInt(0)

        h.putInt(2); h.putInt(112); h.putInt(1); h.putInt(120)

        h.putInt(0); h.putInt(0); h.putInt(0); h.putInt(0)

        h.putInt(1); h.putInt(124); h.putInt(1); h.putInt(132); h.putInt(0); h.putInt(0)

        out.write(h.array())

        val ids = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)

        ids.putInt(164).putInt(180); out.write(ids.array())

        val type = java.nio.ByteBuffer.allocate(4).order(java.nio.ByteOrder.LITTLE_ENDIAN)

        type.putInt(0); out.write(type.array())

        val method = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)

        method.putShort(0).putShort(0).putInt(1); out.write(method.array())

        val cls = java.nio.ByteBuffer.allocate(32).order(java.nio.ByteOrder.LITTLE_ENDIAN)

        cls.putInt(0).putInt(1).putInt(0xFFFFFFFF.toInt()).putInt(0xFFFFFFFF.toInt())

        cls.putInt(0).putInt(0).putInt(0).putInt(214); out.write(cls.array())

        check(out.size() == 164)

        out.write(12); out.write("Lcom/demo/A;".toByteArray(Charsets.US_ASCII)); out.write(0)

        while (out.size() < 180) out.write(0)

        out.write(1); out.write("X".toByteArray(Charsets.US_ASCII)); out.write(0)

        while (out.size() < 196) out.write(0)

        val code = java.nio.ByteBuffer.allocate(18).order(java.nio.ByteOrder.LITTLE_ENDIAN)

        code.putShort(1).putShort(0).putShort(0).putShort(0).putInt(0).putInt(1).putShort(0x000e.toShort())

        out.write(code.array())

        out.write(byteArrayOf(0, 0, 1, 0, 0, 9, 0xC4.toByte(), 0x01))

        val bytes = out.toByteArray()

        java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(32, bytes.size)

        return bytes

    }



    private fun apkWith(vararg entries: Pair<String, ByteArray>): java.io.File {

        val f = tmp.newFile("demo-${System.nanoTime()}.apk")

        ZipOutputStream(f.outputStream()).use { z ->

            entries.forEach { (name, bytes) -> z.putNextEntry(ZipEntry(name)); z.write(bytes) }

        }

        return f

    }



    @Test

    fun parsesMethodBodyAndDecodesReturnVoid() {

        val apk = apkWith("classes.dex" to buildDexWithMethodBody())

        val body = DexInventoryReader.readMethodBody(apk, "classes.dex", 0)

        assertEquals(1, body.registersSize)

        assertEquals(1, body.insnsSize)

        assertEquals(listOf("return-void"), body.lines)

        assertTrue(!body.truncated)

    }



    @Test

    fun rejectsUnknownMethodIndex() {

        val apk = apkWith("classes.dex" to buildDexWithMethodBody())

        assertThrows(DexInspectionException::class.java) { DexInventoryReader.readMethodBody(apk, "classes.dex", 9) }

    }



    @Test

    fun rejectsOversizedInsns() {

        val apk = apkWith("classes.dex" to buildDexWithMethodBody())

        val bytes = buildDexWithMethodBody()

        // insns_size lives at codeOffset+12=208

        java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(208, 2_000_000)

        val badApk = apkWith("classes.dex" to bytes)

        assertThrows(DexInspectionException::class.java) { DexInventoryReader.readMethodBody(badApk, "classes.dex", 0) }

    }

}

