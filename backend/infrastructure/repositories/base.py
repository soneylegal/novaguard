"""
NovaGuard — Repositório Base (CRUD Genérico).

Implementa o Repository Pattern para isolar a camada de negócios
do acesso a dados. Facilita:
  - Testes unitários (mocking do repositório)
  - Troca futura de banco de dados
  - Reutilização de lógica de persistência
"""

from __future__ import annotations

import logging
from typing import Any, Generic, List, Optional, Sequence, Type, TypeVar
from uuid import UUID

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from backend.infrastructure.db.models import Base

logger = logging.getLogger(__name__)

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """
    Repositório CRUD genérico assíncrono.

    Subclasses herdam create, get_by_id, get_all, delete, count
    e podem adicionar métodos específicos de domínio.
    """

    def __init__(self, model: Type[ModelType], session: AsyncSession):
        self.model = model
        self.session = session

    async def create(self, **kwargs: Any) -> ModelType:
        """Cria e persiste uma nova entidade."""
        instance = self.model(**kwargs)
        self.session.add(instance)
        await self.session.flush()
        return instance

    async def get_by_id(self, entity_id: UUID) -> Optional[ModelType]:
        """Busca uma entidade pelo ID primário."""
        return await self.session.get(self.model, entity_id)

    async def get_all(
        self,
        offset: int = 0,
        limit: int = 100,
    ) -> Sequence[ModelType]:
        """Retorna entidades com paginação."""
        stmt = (
            select(self.model)
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def count(self) -> int:
        """Retorna o total de entidades na tabela."""
        stmt = select(func.count()).select_from(self.model)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def delete_by_id(self, entity_id: UUID) -> bool:
        """Remove uma entidade pelo ID. Retorna True se encontrada."""
        instance = await self.get_by_id(entity_id)
        if instance is None:
            return False
        await self.session.delete(instance)
        await self.session.flush()
        return True

    async def bulk_create(self, items: List[dict[str, Any]]) -> int:
        """
        Inserção em lote usando `insert().values()`.
        Drasticamente mais rápido que criar instâncias individuais.

        Returns:
            Número de registros inseridos.
        """
        if not items:
            return 0

        from sqlalchemy import insert
        stmt = insert(self.model).values(items)
        await self.session.execute(stmt)
        await self.session.flush()

        logger.info(
            "Bulk insert: %d records into %s",
            len(items),
            self.model.__tablename__,
        )
        return len(items)

    async def commit(self) -> None:
        """Commita a transação atual."""
        await self.session.commit()

    async def rollback(self) -> None:
        """Reverte a transação atual."""
        await self.session.rollback()
