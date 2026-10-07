package com.cyberintel.repository;

import com.cyberintel.entity.IOC;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;

public interface IocRepository extends JpaRepository<IOC,Long> {
    @Query("select i from IOC i join fetch i.apkAnalysis a join fetch a.scan s join fetch s.user u " +
           "where u.email = :email order by i.createdAt desc, i.id desc")
    List<IOC> findExplorerIocsByUserEmail(@Param("email") String email);

    @Query("select i from IOC i join fetch i.apkAnalysis a join fetch a.scan s join fetch s.user u " +
           "where i.id = :iocId and u.email = :email")
    Optional<IOC> findExplorerIocByIdAndUserEmail(@Param("iocId") Long iocId, @Param("email") String email);

    List<IOC> findByApkAnalysisId(Long apkAnalysisId);

    @Query("select i from IOC i where i.apkAnalysis.id=:aid and i.type=:type")
    List<IOC> findByApkAnalysisIdAndType(@Param("aid") Long apkAnalysisId, @Param("type") String type);

    @Query("select i from IOC i where i.apkAnalysis.id=:aid and i.severity=:sev")
    List<IOC> findByApkAnalysisIdAndSeverity(@Param("aid") Long apkAnalysisId, @Param("sev") String severity);

    long countByApkAnalysisId(Long apkAnalysisId);

    long countByApkAnalysisIdAndType(Long apkAnalysisId, String type);

    boolean existsByApkAnalysisIdAndTypeAndValue(Long apkAnalysisId, String type, String value);

    @Modifying
    @Query("delete from IOC i where i.apkAnalysis.id=:aid")
    void deleteByApkAnalysisId(@Param("aid") Long apkAnalysisId);
}
