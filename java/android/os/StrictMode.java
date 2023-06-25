package android.os;

public class StrictMode {
    public static class ThreadPolicy {
        public static class Builder {
            public Builder() {
            }

            public ThreadPolicy build() {
                return new ThreadPolicy();
            }

            public Builder permitAll() {
                return this;
            }
        }
    }

    public static void setThreadPolicy(ThreadPolicy policy) {
    }
}