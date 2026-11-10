package app.unbraid.linux

import java.io.Closeable
import java.io.File
import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.sql.ResultSet

/** The part of Android's SQLite API the statistics use, over sqlite-jdbc, so that code and its schema stay as they are. */
class SQLiteDatabase(file: File) : Closeable {
    private val c: Connection = DriverManager.getConnection("jdbc:sqlite:${file.path}")

    fun execSQL(sql: String, args: Array<Any> = emptyArray()) { prepare(sql, args).use { it.execute() } }

    fun rawQuery(sql: String, args: Array<String>): Cursor = prepare(sql, args).let { Cursor(it.executeQuery(), it) }

    /** Runs [f] in one transaction: committed if it returns, rolled back if it throws. */
    fun <T> transaction(f: SQLiteDatabase.() -> T): T {
        c.autoCommit = false
        try { return f().also { c.commit() } } catch (e: Throwable) { c.rollback(); throw e } finally { c.autoCommit = true }
    }

    var version: Int
        get() = c.createStatement().use { s -> s.executeQuery("PRAGMA user_version").use { if (it.next()) it.getInt(1) else 0 } }
        set(v) { c.createStatement().use { it.execute("PRAGMA user_version = $v") } }

    override fun close() = c.close()

    private fun prepare(sql: String, args: Array<out Any>): PreparedStatement = c.prepareStatement(sql).apply { args.forEachIndexed { i, a -> setObject(i + 1, a) } }
}

/** A query's rows, read the Android way: [moveToNext], then columns by index from 0. */
class Cursor(private val rs: ResultSet, private val st: PreparedStatement) : Closeable {
    fun moveToNext() = rs.next()
    fun getString(i: Int): String = rs.getString(i + 1)
    fun getInt(i: Int) = rs.getInt(i + 1)
    fun getLong(i: Int) = rs.getLong(i + 1)
    override fun close() { rs.close(); st.close() }
}

/** Android's open helper: creates the file at [version], or upgrades an older one, in one transaction. */
abstract class SQLiteOpenHelper(private val file: File, private val version: Int) : Closeable {
    private var db: SQLiteDatabase? = null

    abstract fun onCreate(d: SQLiteDatabase)
    abstract fun onUpgrade(d: SQLiteDatabase, old: Int, new: Int)

    val writableDatabase: SQLiteDatabase
        @Synchronized get() = db ?: SQLiteDatabase(file).also { d ->
            val (old, want) = d.version to version // named apart: inside the transaction, "version" is the database's own
            if (old != want) d.transaction { if (old == 0) onCreate(this) else onUpgrade(this, old, want); this.version = want }
            db = d
        }

    @Synchronized override fun close() { db?.close(); db = null }
}
