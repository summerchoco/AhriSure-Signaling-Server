-- ================================
-- AhriSure PostgreSQL init SQL (UPDATED)
-- PostgreSQL 16 compatible
-- Storage policy:
--   - Max: 10.000 MB
--   - Min billing: 0.001 MB (handled in server)
--   - DB unit: MB ✅
-- ================================

SET search_path TO public;

-- ================================
-- ENUM TYPES
-- ================================

-- ✅ 서버 코드에 manager 등장하므로 포함(안 쓰면 유지해도 무방)
CREATE TYPE role_type AS ENUM ('user', 'planner', 'admin', 'manager', 'customer');

-- ================================
-- FUNCTIONS
-- ================================

CREATE OR REPLACE FUNCTION gen_uuid()
RETURNS uuid
LANGUAGE sql
AS $$
SELECT (
  substr(md5(random()::text || clock_timestamp()::text), 1, 8) || '-' ||
  substr(md5(random()::text || clock_timestamp()::text), 9, 4) || '-' ||
  substr(md5(random()::text || clock_timestamp()::text), 13, 4) || '-' ||
  substr(md5(random()::text || clock_timestamp()::text), 17, 4) || '-' ||
  substr(md5(random()::text || clock_timestamp()::text), 21, 12)
)::uuid;
$$;

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

-- ✅ [2026-01-19] role별 user_no 자동 할당 트리거 함수
--  - user:   1001부터 자동 증가
--  - planner: 2001부터 자동 증가
--  - admin:  3001부터 자동 증가
--  - 서버가 user_no를 명시하면 그대로 사용
CREATE OR REPLACE FUNCTION assign_user_no_by_role()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  base_no integer;
  max_no  integer;
BEGIN
  IF NEW.user_no IS NOT NULL THEN
    RETURN NEW;
  END IF;

  IF NEW.role = 'user' THEN
    base_no := 1000;
    SELECT COALESCE(MAX(user_no), base_no) INTO max_no FROM users WHERE role = 'user';
    NEW.user_no := max_no + 1;

  ELSIF NEW.role = 'planner' THEN
    base_no := 2000;
    SELECT COALESCE(MAX(user_no), base_no) INTO max_no FROM users WHERE role = 'planner';
    NEW.user_no := max_no + 1;

  ELSIF NEW.role = 'admin' THEN
    base_no := 3000;
    SELECT COALESCE(MAX(user_no), base_no) INTO max_no FROM users WHERE role = 'admin';
    NEW.user_no := max_no + 1;

  ELSE
    -- manager/customer 등은 정책상 user_no 자동할당이 필요하면 여기서 분기 추가 가능
    RAISE EXCEPTION 'Unknown role: %', NEW.role;
  END IF;

  RETURN NEW;
END;
$$;

-- ================================
-- USERS
-- MB unit ✅
-- stored as numeric(12,6)
-- ================================

CREATE TABLE users (
  -- ✅ [2026-01-19] 회원가입 시 id 미전달(또는 NULL)로 인한 23502 방지 → DEFAULT 추가
  id uuid PRIMARY KEY DEFAULT gen_uuid(),

  email text NOT NULL,
  password_hash text,
  name text NOT NULL,
  phone text,

  -- ✅ [2026-01-19] 서버 누락 대비 (원치 않으면 DEFAULT 제거 가능)
  role role_type NOT NULL DEFAULT 'user',

  -- ✅ [2026-01-19] 회원가입 시 is_active 누락 방지 → DEFAULT 추가
  is_active boolean NOT NULL DEFAULT true,

  user_no integer UNIQUE,
  planner_no integer,

  -- Storage (MB) ✅
  file_bytes numeric(12,6) NOT NULL DEFAULT 10.000000,
  used_bytes numeric(12,6) NOT NULL DEFAULT 0.000000,

  intro_text text,

  -- ✅ [2026-01-19] 회원가입 시 created_at/updated_at 누락 방지 → DEFAULT 추가
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT users_email_not_empty
    CHECK (length(trim(email)) > 0),

  CONSTRAINT users_phone_digits
    CHECK (phone IS NULL OR phone ~ '^[0-9]{10,11}$'),

  CONSTRAINT users_file_bytes_nonneg
    CHECK (file_bytes >= 0),

  CONSTRAINT users_used_bytes_nonneg
    CHECK (used_bytes >= 0),

  CONSTRAINT users_used_le_file
    CHECK (used_bytes <= file_bytes),

  -- ✅ [2026-01-19] role별 user_no 범위 체크(원치 않으면 제거 가능)
  CONSTRAINT users_user_no_range_by_role
    CHECK (
      user_no IS NULL OR
      (role = 'user' AND user_no BETWEEN 1001 AND 1999) OR
      (role = 'planner' AND user_no BETWEEN 2001 AND 2999) OR
      (role = 'admin' AND user_no BETWEEN 3001 AND 3999)
    )
);

CREATE UNIQUE INDEX users_email_unique_lower
  ON users (lower(email));

-- ✅ [2026-01-19] INSERT 시 user_no 자동 할당
CREATE TRIGGER users_assign_user_no_trg
BEFORE INSERT ON users
FOR EACH ROW
EXECUTE FUNCTION assign_user_no_by_role();

-- 기존 유지: UPDATE 시 updated_at 자동 갱신
CREATE TRIGGER users_updated_at_trg
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- ================================
-- FILES (uploaded file metadata)
-- - purpose: 삭제 시 sizeBytes/sizeMbCharged 조회
-- - unit policy:
--    size_bytes: BIGINT (raw bytes)
--    size_mb_charged: numeric(12,6) (MB 과금 단위, 최소 0.001)
-- ================================

CREATE TABLE user_files (
  id uuid PRIMARY KEY DEFAULT gen_uuid(),

  -- ✅ [2026-02-26] NEW: 파일 순서/정렬용 file_no (1부터 자동 증가, 전역 유일)
  file_no bigint GENERATED ALWAYS AS IDENTITY,

  -- ✅ [2026-02-26] FIX: 어떤 유저의 파일인지 user_no로 식별 (users.user_no FK)
  user_no integer NOT NULL REFERENCES users(user_no) ON DELETE CASCADE,

  -- ahrirag 쪽 식별 정보(클라에서 metadata로 이미 보내는 값들)
  -- ✅ [2026-02-26] FIX: user_id 컬럼 제거 → user_no로만 식별
  collection_name text NOT NULL,      -- 예: common, ahrisure_customer_1001
  category_path text NOT NULL DEFAULT '',
  content_name text NOT NULL,         -- 파일명
  content_timestamp text,             -- 다운로드/삭제에 쓰는 timestamp가 있으면 저장(없으면 NULL)

  -- 파일 메타
  mime_type text,
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  size_mb_charged numeric(12,6) NOT NULL CHECK (size_mb_charged >= 0),
  uploaded_at timestamptz NOT NULL DEFAULT now(),

  -- 중복 방지용 키(“같은 경로/이름/타임스탬프”를 1개로)
  -- ✅ [2026-02-26] FIX: owner_user_id -> user_no로 변경
  CONSTRAINT user_files_uniq
    UNIQUE (user_no, collection_name, category_path, content_name, content_timestamp),

  -- ✅ [2026-02-26] NEW: file_no 유일 보장(정렬/조회 안정성)
  CONSTRAINT user_files_file_no_uniq
    UNIQUE (file_no)
);

-- 조회 최적화 (삭제/조회는 보통 경로+파일명 기준)
CREATE INDEX user_files_lookup_idx
  ON user_files (collection_name, category_path, content_name);

-- ✅ [2026-02-26] FIX: user_no 기반 조회/조인 최적화
CREATE INDEX user_files_userno_idx
  ON user_files (user_no);

-- ✅ [2026-02-26] NEW: 유저별 최신 파일 정렬 최적화(필요 시)
CREATE INDEX user_files_userno_fileno_idx
  ON user_files (user_no, file_no DESC);

-- ============================================================
-- USERS DATA
-- All users capped at 10.000 MB ✅
-- ============================================================

INSERT INTO users (
  id, email, password_hash, name, phone, role, is_active,
  user_no, planner_no,
  created_at, updated_at, intro_text,
  file_bytes, used_bytes
) VALUES

-- 관리자
('d1733843-3c03-b5ac-54a8-e422c02d808b',
 'admin@example.com', NULL, '관리자', '0212345678',
 'admin', true,
 3001, NULL,
 '2025-11-10 15:12:47.666322+09',
 '2025-11-10 15:12:47.666322+09',
 NULL,
 10.000000, 0.000000),

-- 설계사
('f1ccb24d-75da-4636-e287-220526e0804a',
 'planner@example.com', NULL, '설계사 이지은', '01012345678',
 'planner', true,
 2001, NULL,
 '2025-11-10 15:12:47.666322+09',
 '2025-11-10 15:12:47.666322+09',
 NULL,
 10.000000, 0.000000),

-- 고객
('c81cb455-b459-0420-4f5f-db4576efb3ec',
 'user@example.com', NULL, '고객 김현우', '01087654321',
 'user', true,
 1001, 2001,
 '2025-11-10 15:12:47.666322+09',
 '2025-11-10 15:12:47.666322+09',
 NULL,
 10.000000, 0.000000),

('9bd2595f-e803-7a04-cf6b-75adc425138f',
 'qkraudtn@naver.com',
 '$2b$10$jYd9dhcjXBzT0n3SwUAatej5RGlhmkTfd/gcFU7bndZbI8Ybhj.vq',
 '박명수', '01012345678',
 'user', true,
 1003, 2002,
 '2025-11-10 15:50:16.848108+09',
 '2025-11-10 18:16:16.512337+09',
 NULL,
 10.000000, 0.000000),

('3627c65a-ea95-5f56-9f52-2553df2378e9',
 'dusdnek1@naver.com',
 '$2b$10$U7.nPhFbZ4crHRJRq5X/Oev0j6K38gNCzCxEepYeXZSJBWMhNbKa6',
 '유수영', '01012345678',
 'user', true,
 1004, 2002,
 '2025-11-10 15:51:21.423813+09',
 '2025-11-10 18:16:49.928379+09',
 NULL,
 10.000000, 0.000000),

('6088bcd7-9caa-af13-42e6-e0cba5bc33bd',
 'wjdgudehs@naver.com',
 '$2b$10$o1sJOFiOKpIgwKd1vpXTL.RzTyzld5A68O11pR30bQk686RwJHx2K',
 '정형돈', '01012345678',
 'user', true,
 1005, 2002,
 '2025-11-10 17:11:30.883272+09',
 '2025-11-13 16:15:06.162531+09',
 NULL,
 10.000000, 0.000000),

('38871cc3-06f6-ebe4-4957-c2508a5d7fa8',
 'pyj1020@bns.co.kr',
 '$2b$10$NZAzhHVJMLTPDRAXJ8aZWuTBLZgCDi8EOkORCryUBpjf/eVMU5PmK',
 '박용진', '01051684201',
 'user', true,
 1006, 2002,
 '2025-11-27 16:34:09.852632+09',
 '2025-11-27 16:37:02.33422+09',
 NULL,
 10.000000, 0.000000),

('fdc77557-2116-6c87-f45f-7e49fee17e12',
 'testleele@naver.com',
 '$2b$10$wARK7UT5fyJmZz73HA36.OOh5IWg2LIDmNo/MffMQv6GpnzCJxB2S',
 '최영리', '01000000000',
 'user', true,
 1007, 2002,
 '2025-11-27 16:52:16.350128+09',
 '2025-11-27 16:52:16.350128+09',
 NULL,
 10.000000, 0.000000),

-- 초과 데이터 캡(예시: 10MB 꽉 찬 상태로 넣고 싶으면 이렇게)
('f9e3363c-fdab-9141-d131-fdb47fae616a',
 'wjdwnsgk@naver.com',
 '$2b$10$kuvBYB/PvjBUMDr8sMpI2.s0anzTl2/wjU7xU/YKGkJslNKR8E7Ze',
 '정준하', '01012345678',
 'user', true,
 1002, 2002,
 '2025-11-10 15:13:50.30786+09',
 '2025-12-10 17:02:50.44447+09',
 NULL,
 10.000000, 0.000000),

-- 설계사
('478c7ac9-aed6-1520-c80c-c7d54146d3f2',
 'dbwotjr@naver.com',
 '$2b$10$f8TC1uaGAZw7U79MAlUzWehLi6T/EEU77rySM24CpZEWkA3E6HaHi',
 '유재석', '01012345678',
 'planner', true,
 2002, NULL,
 '2025-11-10 17:45:05.400489+09',
 '2025-12-11 14:46:53.257098+09',
 NULL,
 10.000000, 0.000000);