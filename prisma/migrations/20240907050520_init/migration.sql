-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "email" TEXT NOT NULL,
    "hash" TEXT NOT NULL,
    "hashedRTK" TEXT,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);
